package com.minisoc.incidents.dto;

import com.minisoc.incidents.domain.Incident;
import com.minisoc.incidents.domain.IncidentSource;
import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;

import java.time.Instant;

public record IncidentSummary(
        Long id,
        String title,
        Severity severity,
        IncidentStatus status,
        IncidentSource source,
        String ruleId,
        String affectedUser,
        String sourceIp,
        String assignee,
        int detectionCount,
        Instant detectedAt,
        Instant createdAt,
        Instant updatedAt) {

    public static IncidentSummary from(Incident i) {
        return new IncidentSummary(i.getId(), i.getTitle(), i.getSeverity(), i.getStatus(), i.getSource(),
                i.getRuleId(), i.getAffectedUser(), i.getSourceIp(), i.getAssignee(), i.getDetectionCount(),
                i.getDetectedAt(), i.getCreatedAt(), i.getUpdatedAt());
    }
}
