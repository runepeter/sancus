package org.brylex.sancus.cli.output;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.brylex.sancus.audit.AuditReport;
import org.brylex.sancus.audit.Finding;

import java.io.PrintStream;
import java.time.format.DateTimeFormatter;

public final class JsonOutputFormatter implements OutputFormatter {

    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ISO_INSTANT;

    @Override
    public void format(AuditReport report, PrintStream out) {
        var root = new JsonObject();
        root.addProperty("host", report.host());
        root.addProperty("port", report.port());
        root.addProperty("timestamp", ISO_FMT.format(report.timestamp()));
        root.addProperty("overallSeverity", report.overallSeverity().name());
        root.addProperty("exitCode", report.exitCode());

        var findings = new JsonArray();
        for (Finding f : report.findings()) {
            var obj = new JsonObject();
            obj.addProperty("type", findingType(f));
            obj.addProperty("severity", f.severity().name());
            obj.addProperty("summary", f.summary());
            findings.add(obj);
        }
        root.add("findings", findings);

        var gson = new GsonBuilder().setPrettyPrinting().create();
        out.println(gson.toJson(root));
    }

    private static String findingType(Finding finding) {
        return switch (finding) {
            case Finding.ExpiryFinding _ -> "expiry";
            case Finding.RevocationFinding _ -> "revocation";
            case Finding.WeakAlgorithmFinding _ -> "algorithm";
            case Finding.ChainFinding _ -> "chain";
            case Finding.ProtocolFinding _ -> "protocol";
            case Finding.TransparencyFinding _ -> "transparency";
        };
    }
}
