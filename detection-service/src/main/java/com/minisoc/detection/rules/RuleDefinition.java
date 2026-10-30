package com.minisoc.detection.rules;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * A threshold detection rule: "at least {@code threshold} events matching {@code match}
 * (and not matching {@code exclude}) for the same {@code groupBy} value within {@code window}".
 * Rules are declared in application.yml so new detections need no code changes.
 *
 * @param match        field -> accepted values (terms filter), all fields must match
 * @param exclude      field -> values that disqualify an event
 * @param pathPrefix   optional prefix filter on http_path
 * @param escalateAt   count at which severity is raised to {@code escalateTo}
 * @param suppress     how long to stay quiet for the same entity after firing (defaults to window)
 * @param mitre        MITRE ATT&CK technique id, for analyst context
 * @param require      field -> values; the group must contain at least one matching event
 *                     (e.g. a LOGIN_SUCCESS among the failures for account takeover)
 * @param distinctField when set, the group must also have at least {@code minDistinct}
 *                     different values of this field (e.g. many source IPs for one user)
 */
public record RuleDefinition(
        @NotBlank String id,
        @NotBlank String name,
        String description,
        @NotNull Severity severity,
        @NotNull Duration window,
        @Min(1) int threshold,
        @NotBlank String groupBy,
        Map<String, List<String>> match,
        Map<String, List<String>> exclude,
        String pathPrefix,
        Integer escalateAt,
        Severity escalateTo,
        Duration suppress,
        String mitre,
        Boolean enabled,
        Map<String, List<String>> require,
        String distinctField,
        Integer minDistinct) {

    public RuleDefinition {
        if (match == null) match = Map.of();
        if (exclude == null) exclude = Map.of();
        if (suppress == null) suppress = window;
        if (enabled == null) enabled = true;
        if (require == null) require = Map.of();
    }

    public boolean hasDistinctCondition() {
        return distinctField != null && !distinctField.isBlank() && minDistinct != null;
    }

    public Severity severityFor(long count) {
        if (escalateAt != null && escalateTo != null && count >= escalateAt) return escalateTo;
        return severity;
    }
}
