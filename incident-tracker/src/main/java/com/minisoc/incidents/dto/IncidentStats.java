package com.minisoc.incidents.dto;

import java.util.List;
import java.util.Map;

public record IncidentStats(
        long total,
        long active,
        long unassignedActive,
        long createdLast24h,
        long resolvedLast24h,
        Double meanTimeToAcknowledgeMinutes,
        Double meanTimeToResolveMinutes,
        Map<String, Long> byStatus,
        Map<String, Long> bySeverity,
        Map<String, Long> activeBySeverity,
        List<Count> topAffectedUsers,
        List<Count> topSourceIps,
        List<Count> topRules) {

    public record Count(String key, long count) {
    }
}
