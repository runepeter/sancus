package org.brylex.sancus.audit.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.brylex.sancus.audit.AuditReport;
import org.brylex.sancus.audit.Finding;
import org.brylex.sancus.audit.Finding.*;
import org.brylex.sancus.audit.Severity;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class OutputFormatterTest {

    private static final List<Finding> ALL_FINDING_TYPES = List.of(
            new ExpiryFinding("CN=example.com", Severity.WARNING, 22, Instant.now()),
            new ProtocolFinding(Severity.OK, "TLSv1.3", "TLS_AES_256_GCM_SHA384"),
            new WeakAlgorithmFinding("CN=example.com", Severity.OK, "SHA256withRSA", 2048),
            new ChainFinding(Severity.OK, 3, true, List.of()),
            new RevocationFinding("CN=example.com", Severity.OK, "good", "http://ocsp.example.com"),
            new TransparencyFinding("CN=example.com", Severity.OK, 3)
    );

    private static final AuditReport REPORT = new AuditReport(
            "example.com", 443, Instant.parse("2026-04-07T12:00:00Z"), ALL_FINDING_TYPES
    );

    private String formatToString(OutputFormatter formatter) {
        var baos = new ByteArrayOutputStream();
        formatter.format(REPORT, new PrintStream(baos, true, StandardCharsets.UTF_8));
        return baos.toString(StandardCharsets.UTF_8);
    }

    @Nested
    class AnsiOutputFormatterTest {

        @Test
        void containsAnsiEscapeCodes() {
            String output = formatToString(new AnsiOutputFormatter());
            assertTrue(output.contains("\u001B["), "Output should contain ANSI escape codes");
        }

        @Test
        void displaysAllSixFindingTypes() {
            String output = formatToString(new AnsiOutputFormatter());
            assertTrue(output.contains("Expiry"), "Should contain Expiry finding");
            assertTrue(output.contains("Protocol"), "Should contain Protocol finding");
            assertTrue(output.contains("WeakAlgorithm"), "Should contain WeakAlgorithm finding");
            assertTrue(output.contains("ChainCompleteness"), "Should contain ChainCompleteness finding");
            assertTrue(output.contains("OCSP"), "Should contain OCSP finding");
            assertTrue(output.contains("Transparency"), "Should contain Transparency finding");
        }

        @Test
        void displaysHostAndPort() {
            String output = formatToString(new AnsiOutputFormatter());
            assertTrue(output.contains("example.com:443"));
        }

        @Test
        void displaysOverallSeverityAndExitCode() {
            String output = formatToString(new AnsiOutputFormatter());
            assertTrue(output.contains("WARNING"));
            assertTrue(output.contains("exit code 1"));
        }

        @Test
        void usesCorrectSymbols() {
            String output = formatToString(new AnsiOutputFormatter());
            assertTrue(output.contains("\u2713"), "Should contain checkmark for OK");
            assertTrue(output.contains("\u26A0"), "Should contain warning symbol for WARNING");
        }

        @Test
        void criticalUsesXSymbol() {
            var report = new AuditReport("fail.com", 443, Instant.now(),
                    List.of(new ExpiryFinding("CN=fail.com", Severity.CRITICAL, -1, Instant.now())));
            var baos = new ByteArrayOutputStream();
            new AnsiOutputFormatter().format(report, new PrintStream(baos, true, StandardCharsets.UTF_8));
            String output = baos.toString(StandardCharsets.UTF_8);
            assertTrue(output.contains("\u2717"), "Should contain X symbol for CRITICAL");
        }
    }

    @Nested
    class JsonOutputFormatterTest {

        @Test
        void producesValidJson() {
            String output = formatToString(new JsonOutputFormatter());
            assertDoesNotThrow(() -> JsonParser.parseString(output));
        }

        @Test
        void containsRequiredTopLevelFields() {
            String output = formatToString(new JsonOutputFormatter());
            JsonObject json = JsonParser.parseString(output).getAsJsonObject();

            assertEquals("example.com", json.get("host").getAsString());
            assertEquals(443, json.get("port").getAsInt());
            assertEquals("2026-04-07T12:00:00Z", json.get("timestamp").getAsString());
            assertEquals("WARNING", json.get("overallSeverity").getAsString());
            assertEquals(1, json.get("exitCode").getAsInt());
            assertTrue(json.has("findings"));
        }

        @Test
        void findingsContainTypeField() {
            String output = formatToString(new JsonOutputFormatter());
            JsonObject json = JsonParser.parseString(output).getAsJsonObject();
            JsonArray findings = json.getAsJsonArray("findings");

            assertEquals(6, findings.size());

            List<String> expectedTypes = List.of("expiry", "protocol", "algorithm", "chain", "revocation", "transparency");
            for (int i = 0; i < findings.size(); i++) {
                JsonObject finding = findings.get(i).getAsJsonObject();
                assertTrue(finding.has("type"), "Finding should have type field");
                assertTrue(finding.has("severity"), "Finding should have severity field");
                assertTrue(finding.has("summary"), "Finding should have summary field");
                assertEquals(expectedTypes.get(i), finding.get("type").getAsString());
            }
        }

        @Test
        void findingsHaveCorrectStructure() {
            String output = formatToString(new JsonOutputFormatter());
            JsonObject json = JsonParser.parseString(output).getAsJsonObject();
            JsonObject first = json.getAsJsonArray("findings").get(0).getAsJsonObject();

            assertEquals("expiry", first.get("type").getAsString());
            assertEquals("WARNING", first.get("severity").getAsString());
            assertTrue(first.get("summary").getAsString().contains("22 days"));
        }
    }
}
