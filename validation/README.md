# Database vendor validation

Run the real compiled DAO with each packaged vendor mapper in a newly created,
uniquely labeled Docker container. This supplements the maintained Derby/JUnit
suite; it does not start an engine or claim complete deployed-engine coverage.
Identity and encryption use explicit deterministic fixture seams, while SQL,
transactions, row locks, JDBC drivers, migrations, and persisted state are real.

Prerequisites: a successful `mvn verify` (compiled classes and Surefire classpath),
JDK 17+, Python 3.9+, Docker, engine JDBC drivers, and these cached image tags:
`postgres:17.10-alpine`, `mysql:8.4.11`,
`gvenzl/oracle-free:23.26.1-faststart`,
`mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04`.
SQL Server requires amd64 support/emulation. Images are never pulled.

```sh
python3 validation/run-vendor-databases.py \
  --java-home /path/to/jdk \
  --drivers /path/to/engine/server-lib/database \
  --evidence /path/to/new-evidence-directory
```

Use `--vendors postgres mysql` to select a subset. Images run sequentially with
3 GiB memory and 2 CPUs each, published only on a randomly assigned loopback port.
The runner takes no external database URL and uses no bind mounts or shared
volumes. Do not run the Java harness directly against an existing database: its
scenario setup drops the plugin tables in the owned container between checks.

Nine scenarios per vendor cover clean startup/restart, enrollment/verification,
OTP and challenge replay, generation-aware reset/retry, both legacy schemas,
interrupted/resumed and ambiguous migration, concurrent first challenges,
concurrent enrollment/verification, and distributed attempt accounting/cooldown.
Each scenario captures final row observations with secret hashes, never secrets.
The harness uses bounded MyBatis connection reuse and closes the pool before
exiting, matching the engine and avoiding Oracle listener churn from unpooled
connections.

The evidence directory retains compile output, immutable class/mapper snapshots,
source/runtime/driver hashes, image provenance, logs, row observations, container
process receipts, and cleanup manifests. After checks finish, the runner captures
evidence, checks the exact container ID and ownership label, stops it, verifies
no process remains, removes it with anonymous volumes, and verifies absence.
Cleanup refuses ownership or process-state uncertainty and reports the remaining
resource rather than touching unrelated resources.
