#!/usr/bin/env python3
"""Run actual TOTP DAO/mappers in disposable, uniquely owned Docker databases.

Requires cached images, a successful Maven test compile, a JDK, and the engine's
existing JDBC drivers. Never pulls images or mounts shared files into containers.
Every container is captured, stopped, and removed with its anonymous volumes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
OWNER_LABEL = "org.openintegrationengine.totp.validation-owner"
VENDORS = {
    "postgres": {"image": "postgres:17.10-alpine", "port": 5432, "driver": "org.postgresql.Driver", "jar": "postgresql-42.7.12.jar"},
    "mysql": {"image": "mysql:8.4.11", "port": 3306, "driver": "com.mysql.cj.jdbc.Driver", "jar": "mysql-connector-j-8.4.0.jar"},
    "oracle": {"image": "gvenzl/oracle-free:23.26.1-faststart", "port": 1521, "driver": "oracle.jdbc.OracleDriver", "jar": "ojdbc8-12.2.0.1.jar"},
    "sqlserver": {"image": "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04", "port": 1433, "driver": "com.microsoft.sqlserver.jdbc.SQLServerDriver", "jar": "mssql-jdbc-10.2.4.jre11.jar"},
}


def command(args, *, env=None, timeout=60, check=True, cwd=None):
    result = subprocess.run(args, cwd=cwd or ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command {args[0:2]} failed ({result.returncode}):\n{result.stdout}")
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_owned(container, owner):
    result = command(["docker", "inspect", container])
    value = json.loads(result.stdout)[0]
    if value["Config"]["Labels"].get(OWNER_LABEL) != owner or value["Id"] != container:
        raise RuntimeError(f"REFUSING cleanup: ownership mismatch for {container}")
    return value


def cleanup(container, owner, evidence):
    receipt = {"container": container, "owner": owner}
    try:
        inspected = inspect_owned(container, owner)
        write_json(evidence / "container-before-cleanup.json", inspected)
        logs = command(["docker", "logs", "--timestamps", container], check=False)
        (evidence / "container.log").write_text(logs.stdout)
        receipt["anonymousVolumes"] = [m["Name"] for m in inspected.get("Mounts", []) if m["Type"] == "volume"]
        # Captured evidence first; terminate only the ID whose ownership matched.
        stop = command(["docker", "stop", "--time", "20", container], timeout=45, check=False)
        receipt["stop"] = {"returncode": stop.returncode, "output": stop.stdout}
        stopped = inspect_owned(container, owner)
        receipt["finalState"] = stopped["State"]
        write_json(evidence / "container-stopped.json", stopped)
        if stopped["State"]["Running"] or stopped["State"]["Pid"] != 0:
            raise RuntimeError(f"REFUSING removal: container process still active: {container}")
        removed = command(["docker", "rm", "-v", container])
        receipt["remove"] = removed.stdout.strip()
        absent = command(["docker", "inspect", container], check=False)
        receipt["containerAbsent"] = absent.returncode != 0 and "No such object" in absent.stdout
        receipt["volumeAbsence"] = {}
        for volume in receipt["anonymousVolumes"]:
            observed = command(["docker", "volume", "inspect", volume], check=False)
            receipt["volumeAbsence"][volume] = observed.returncode != 0 and "no such volume" in observed.stdout.lower()
        if not receipt["containerAbsent"] or not all(receipt["volumeAbsence"].values()):
            raise RuntimeError("Cleanup absence verification failed")
        receipt["status"] = "removed-after-observation"
    except Exception as error:
        receipt["status"] = "cleanup-blocked"
        receipt["error"] = str(error)
        raise
    finally:
        write_json(evidence / "cleanup.json", receipt)


def run_vendor(vendor, spec, args, common_cp, owner):
    evidence = args.evidence / vendor
    evidence.mkdir()
    image = json.loads(command(["docker", "image", "inspect", spec["image"]]).stdout)[0]
    write_json(evidence / "image.json", image)
    password = "Totp-" + secrets.token_hex(12) + "!"
    config = {"postgres": {"POSTGRES_PASSWORD": password, "POSTGRES_DB": "totp"},
              "mysql": {"MYSQL_ROOT_PASSWORD": password, "MYSQL_DATABASE": "totp"},
              "oracle": {"ORACLE_PASSWORD": password, "APP_USER": "totp", "APP_USER_PASSWORD": password},
              "sqlserver": {"ACCEPT_EULA": "Y", "MSSQL_SA_PASSWORD": password, "MSSQL_PID": "Developer"}}[vendor]
    create = ["docker", "create", "--pull=never", "--name", owner + "-" + vendor,
              "--label", OWNER_LABEL + "=" + owner, "--memory", "3g", "--cpus", "2",
              "-p", f"127.0.0.1::{spec['port']}"]
    if vendor == "sqlserver":
        create += ["--platform", "linux/amd64"]
    for key, value in config.items():
        create += ["-e", key + "=" + value]
    create.append(spec["image"])
    container = command(create).stdout.strip()
    receipt = {"vendor": vendor, "owner": owner, "container": container, "image": image["Id"], "status": "created"}
    write_json(evidence / "run.json", receipt)
    try:
        inspect_owned(container, owner)
        command(["docker", "start", container])
        inspected = inspect_owned(container, owner)
        write_json(evidence / "container-started.json", inspected)
        bindings = inspected["NetworkSettings"]["Ports"][str(spec["port"]) + "/tcp"]
        if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
            raise RuntimeError("Unexpected non-loopback port binding")
        port = bindings[0]["HostPort"]
        url = {
            "postgres": f"jdbc:postgresql://127.0.0.1:{port}/totp?connectTimeout=5&socketTimeout=35",
            "mysql": f"jdbc:mysql://127.0.0.1:{port}/totp?useSSL=false&allowPublicKeyRetrieval=true&connectTimeout=5000&socketTimeout=35000&serverTimezone=UTC",
            "oracle": f"jdbc:oracle:thin:@//127.0.0.1:{port}/FREEPDB1",
            "sqlserver": f"jdbc:sqlserver://127.0.0.1:{port};databaseName=master;encrypt=false;trustServerCertificate=true;loginTimeout=5;socketTimeout=35000"
        }[vendor]
        user = {"postgres": "postgres", "mysql": "root", "oracle": "totp", "sqlserver": "sa"}[vendor]
        env = os.environ | {"TOTP_VENDOR": vendor, "TOTP_JDBC_URL": url, "TOTP_DB_USER": user,
                           "TOTP_DB_PASSWORD": password, "TOTP_JDBC_DRIVER": spec["driver"], "TOTP_OWNED_VALIDATION": owner}
        driver = args.drivers / spec["jar"]
        cp = common_cp + os.pathsep + str(driver)
        invocation = [str(args.java_home / "bin/java"), "-Doracle.net.CONNECT_TIMEOUT=5000", "-Doracle.jdbc.ReadTimeout=35000",
                      "-cp", cp, "org.openintegrationengine.plugins.totp.TotpVendorDatabaseCheck"]
        receipt |= {"jdbcDriver": str(driver), "jdbcDriverSha256": digest(driver), "url": url}
        write_json(evidence / "run.json", receipt)
        deadline = time.monotonic() + args.startup_timeout
        probes = []
        while True:
            probe = command(invocation + ["--probe"], env=env, timeout=15, check=False, cwd=args.evidence)
            probes.append({"returncode": probe.returncode, "output": probe.stdout})
            if probe.returncode == 0:
                break
            if not inspect_owned(container, owner)["State"]["Running"]:
                raise RuntimeError("Database container exited before JDBC readiness")
            if time.monotonic() >= deadline:
                raise RuntimeError("Database JDBC startup timed out")
            time.sleep(3)
        write_json(evidence / "jdbc-probes.json", probes)
        print(f"{vendor}: JDBC ready; checking actual DAO/mappers", flush=True)
        run = command(invocation, env=env, timeout=600, check=False, cwd=args.evidence)
        (evidence / "checks.log").write_text(run.stdout)
        receipt |= {"testExitCode": run.returncode, "status": "passed" if run.returncode == 0 else "failed"}
        print(f"{vendor}: {receipt['status']}", flush=True)
        return run.returncode == 0
    except Exception as error:
        receipt |= {"status": "failed", "error": str(error)}
        if isinstance(error, subprocess.TimeoutExpired) and error.stdout:
            output = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout
            (evidence / "timeout-output.log").write_text(output)
        if "probes" in locals():
            write_json(evidence / "jdbc-probes.json", probes)
        print(f"{vendor}: failed: {error}", flush=True)
        return False
    finally:
        write_json(evidence / "run.json", receipt)
        cleanup(container, owner, evidence)
        print(f"{vendor}: owned container and anonymous volumes removed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drivers", type=Path, required=True, help="Engine server-lib/database (read-only inputs)")
    parser.add_argument("--evidence", type=Path, required=True, help="New evidence directory; must not already exist")
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--vendors", nargs="+", choices=list(VENDORS), default=list(VENDORS))
    parser.add_argument("--startup-timeout", type=int, default=240)
    args = parser.parse_args()
    args.evidence = args.evidence.resolve()
    args.drivers = args.drivers.resolve()
    args.evidence.mkdir(parents=True, exist_ok=False)
    owner = "totp-vendor-" + uuid.uuid4().hex[:12]
    # Capture immutable compiled classes separately so another build cannot alter
    # a running check's code. Read the already-produced Maven runtime classpath.
    report = ROOT / "target/surefire-reports/TEST-org.openintegrationengine.plugins.totp.TotpCredentialDaoTest.xml"
    properties = {e.attrib["name"]: e.attrib["value"] for e in ET.parse(report).findall(".//property")}
    inputs = [Path(p) for p in properties["java.class.path"].split(os.pathsep) if p and p.endswith(".jar")]
    classes = args.evidence / "classes"
    shutil.copytree(ROOT / "target/classes", classes)
    shutil.copytree(ROOT / "mapper", args.evidence / "mapper")
    shutil.copytree(ROOT / "src/main/java", args.evidence / "production-source")
    cp = os.pathsep.join([str(classes)] + [str(p) for p in inputs])
    source = ROOT / "validation/java/org/openintegrationengine/plugins/totp/TotpVendorDatabaseCheck.java"
    shutil.copy2(source, args.evidence / "harness.java")
    shutil.copy2(Path(__file__).resolve(), args.evidence / "runner.py")
    compiled = command([str(args.java_home / "bin/javac"), "--release", "17", "-cp", cp, "-d", str(classes), str(source)])
    (args.evidence / "compile.log").write_text(compiled.stdout)
    tracked = list((ROOT / "src/main/java").rglob("*.java")) + list((ROOT / "mapper").glob("*.xml")) + [source, Path(__file__).resolve()]
    write_json(args.evidence / "source-sha256.json", {str(p.relative_to(ROOT)): digest(p) for p in tracked})
    write_json(args.evidence / "compiled-sha256.json", {str(p.relative_to(classes)): digest(p) for p in classes.rglob("*.class")})
    write_json(args.evidence / "classpath-inputs.json", {str(p): digest(p) for p in inputs})
    (args.evidence / "docker-version.json").write_text(command(["docker", "version", "--format", "{{json .}}"]).stdout)
    summary = {"owner": owner, "vendors": {}}
    for vendor in args.vendors:
        summary["vendors"][vendor] = run_vendor(vendor, VENDORS[vendor], args, cp, owner)
        write_json(args.evidence / "summary.json", summary)
    return 0 if all(summary["vendors"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
