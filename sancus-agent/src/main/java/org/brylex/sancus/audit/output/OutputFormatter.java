package org.brylex.sancus.audit.output;

import org.brylex.sancus.audit.AuditReport;

import java.io.PrintStream;

public sealed interface OutputFormatter permits AnsiOutputFormatter, JsonOutputFormatter {

    void format(AuditReport report, PrintStream out);

    static OutputFormatter forFormat(OutputFormat format) {
        return switch (format) {
            case ANSI -> new AnsiOutputFormatter();
            case JSON -> new JsonOutputFormatter();
        };
    }
}
