package org.brylex.sancus.audit;

public enum Severity implements Comparable<Severity> {
    OK,
    WARNING,
    CRITICAL;

    public int exitCode() {
        return switch (this) {
            case OK -> 0;
            case WARNING -> 1;
            case CRITICAL -> 2;
        };
    }
}
