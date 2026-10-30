package com.minisoc.detection.rules;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** A fired detection. Persisted to the alert index and forwarded to the incident tracker. */
public record DetectionAlert(
        String alertId,
        @JsonProperty("@timestamp") Instant timestamp,
        String ruleId,
        String ruleName,
        String description,
        Severity severity,
        String mitre,
        String groupBy,
        String entity,
        long count,
        Long distinctCount,
        int threshold,
        String window,
        Instant firstSeen,
        Instant lastSeen,
        List<String> sourceIps,
        List<String> usernames,
        List<String> paths,
        List<Map<String, Object>> samples,
        Long incidentId) {

    public String fingerprint() {
        return ruleId + ":" + groupBy + ":" + entity;
    }

    public String title() {
        return "%s - %s %s (%d events in %s)".formatted(ruleName, label(groupBy), entity, count, window);
    }

    private static String label(String field) {
        return switch (field) {
            case "username" -> "user";
            case "source_ip" -> "IP";
            default -> field;
        };
    }

    public DetectionAlert withIncidentId(Long id) {
        return new DetectionAlert(alertId, timestamp, ruleId, ruleName, description, severity, mitre, groupBy, entity,
                count, distinctCount, threshold, window, firstSeen, lastSeen, sourceIps, usernames, paths, samples, id);
    }
}
