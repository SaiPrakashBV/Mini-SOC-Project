package com.minisoc.incidents.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * Incident lifecycle. Allowed transitions:
 * <pre>
 * OPEN ──► INVESTIGATING ──► CONTAINED ──► RESOLVED ──► CLOSED
 *   │            │                              ▲
 *   └────────────┴──► FALSE_POSITIVE ──► CLOSED │
 * RESOLVED / FALSE_POSITIVE / CLOSED can be re-opened to INVESTIGATING.
 * </pre>
 */
public enum IncidentStatus {
    OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE, CLOSED;

    public Set<IncidentStatus> allowedTransitions() {
        return switch (this) {
            case OPEN -> EnumSet.of(INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE);
            case INVESTIGATING -> EnumSet.of(CONTAINED, RESOLVED, FALSE_POSITIVE);
            case CONTAINED -> EnumSet.of(INVESTIGATING, RESOLVED);
            case RESOLVED -> EnumSet.of(CLOSED, INVESTIGATING);
            case FALSE_POSITIVE -> EnumSet.of(CLOSED, INVESTIGATING);
            case CLOSED -> EnumSet.of(INVESTIGATING);
        };
    }

    public boolean canTransitionTo(IncidentStatus target) {
        return allowedTransitions().contains(target);
    }

    /** Statuses that still require analyst work. */
    public boolean isActive() {
        return this == OPEN || this == INVESTIGATING || this == CONTAINED;
    }

    public static Set<IncidentStatus> activeStatuses() {
        return EnumSet.of(OPEN, INVESTIGATING, CONTAINED);
    }

    /** Statuses that require a resolution summary. */
    public boolean requiresResolution() {
        return this == RESOLVED || this == FALSE_POSITIVE;
    }
}
