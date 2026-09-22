/* SPDX-License-Identifier: MPL-2.0 */
package org.openintegrationengine.plugins.totp;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import javax.xml.parsers.DocumentBuilderFactory;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/** Checks the actual distributable after package, including dependency isolation. */
class DistributionIT {
    @Test
    void archiveContainsOnlyThePluginAndRequiredRuntimeResources() throws Exception {
        Map<String, byte[]> files = new HashMap<>();
        try (ZipFile zip = new ZipFile(Path.of(System.getProperty("extension.zip")).toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                if (!entry.isDirectory()) {
                    try (var in = zip.getInputStream(entry)) {
                        assertNull(files.put(entry.getName(), in.readAllBytes()), "Duplicate ZIP entry");
                    }
                }
            }
        }
        assertEquals(Set.of("totpmfa/plugin.xml", "totpmfa/totpmfa-shared.jar",
            "totpmfa/webadmin/plugin.json", "totpmfa/webadmin/web/plugin.js",
            "totpmfa/mapper/derby-usertotp.xml", "totpmfa/mapper/mysql-usertotp.xml",
            "totpmfa/mapper/postgres-usertotp.xml", "totpmfa/mapper/sqlserver-usertotp.xml",
            "totpmfa/mapper/oracle-usertotp.xml"), files.keySet(),
            "Do not ship engine JARs, test dependencies, source, node_modules, or build tools");

        var xmlFactory = DocumentBuilderFactory.newInstance();
        xmlFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        var descriptor = xmlFactory.newDocumentBuilder().parse(new ByteArrayInputStream(files.get("totpmfa/plugin.xml")));
        assertEquals("totpmfa", descriptor.getDocumentElement().getAttribute("path"));
        var web = new ObjectMapper().readTree(files.get("totpmfa/webadmin/plugin.json"));
        assertEquals(descriptor.getElementsByTagName("pluginVersion").item(0).getTextContent(), web.path("version").asText());
        assertTrue(files.containsKey("totpmfa/webadmin/" + web.path("client").path("entry").asText()));
        var mapperEntries = descriptor.getElementsByTagName("entry");
        for (int i = 0; i < mapperEntries.getLength(); i++) {
            var strings = ((org.w3c.dom.Element) mapperEntries.item(i)).getElementsByTagName("string");
            if (strings.getLength() == 2) assertTrue(files.containsKey("totpmfa/" + strings.item(1).getTextContent()));
        }
        var libraries = descriptor.getElementsByTagName("library");
        assertEquals(1, libraries.getLength(), "Only our own JAR is needed at runtime");
        assertTrue(files.containsKey("totpmfa/" + libraries.item(0).getAttributes().getNamedItem("path").getTextContent()));

        Set<String> classes = new java.util.HashSet<>();
        Set<String> sourceClasses = new java.util.HashSet<>();
        try (var sources = Files.walk(Path.of("src/main/java"))) {
            sources.filter(p -> p.toString().endsWith(".java")).forEach(p -> sourceClasses.add(
                Path.of("src/main/java").relativize(p).toString().replace('\\', '/').replaceAll("\\.java$", "")));
        }
        try (var jar = new ZipInputStream(new ByteArrayInputStream(files.get("totpmfa/totpmfa-shared.jar")))) {
            for (var entry = jar.getNextEntry(); entry != null; entry = jar.getNextEntry()) {
                if (entry.isDirectory()) continue;
                String name = entry.getName();
                if (name.startsWith("META-INF/")) continue;
                assertTrue(name.startsWith("org/openintegrationengine/plugins/totp/") && name.endsWith(".class"),
                    "Unexpected bundled dependency/resource: " + name);
                assertFalse(name.endsWith("Test.class") || name.endsWith("IT.class"), "Tests must not ship: " + name);
                assertTrue(sourceClasses.contains(name.replaceFirst("(?:\\$.*)?\\.class$", "")),
                    "Class has no production source: " + name);
                byte[] bytecode = jar.readAllBytes();
                assertEquals(61, ((bytecode[6] & 255) << 8) | (bytecode[7] & 255), "Require Java 17 bytecode");
                classes.add(name);
            }
        }
        assertFalse(classes.isEmpty());
        var serverClasses = descriptor.getElementsByTagName("serverClasses").item(0).getChildNodes();
        for (int i = 0; i < serverClasses.getLength(); i++) {
            if (serverClasses.item(i).getNodeName().equals("string")) {
                assertTrue(classes.contains(serverClasses.item(i).getTextContent().replace('.', '/') + ".class"));
            }
        }
        var providers = descriptor.getElementsByTagName("apiProvider");
        for (int i = 0; i < providers.getLength(); i++) {
            String className = providers.item(i).getAttributes().getNamedItem("name").getTextContent();
            assertTrue(classes.contains(className.replace('.', '/') + ".class"), className);
        }
        String script = new String(files.get("totpmfa/webadmin/web/plugin.js"), StandardCharsets.UTF_8);
        assertTrue(script.contains("from \"@oie/web-shell\"") || script.contains("from '@oie/web-shell'"),
            "Host framework must remain an external import");
        assertFalse(script.contains("node_modules/react/"), "Do not embed another React instance");
    }
}
