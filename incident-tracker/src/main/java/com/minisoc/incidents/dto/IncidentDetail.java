package com.minisoc.incidents.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.incidents.domain.Incident;
import com.minisoc.incidents.domain.IncidentHistory;
import com.minisoc.incidents.domain.IncidentNote;
import com.minisoc.incidents.domain.IncidentSource;
import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public record IncidentDetail(
        Long id,
        String title,
        String description,
        Severity severity,
        IncidentStatus status,
        Set<IncidentStatus> allowedTransitions,
        IncidentSource source,
        String ruleId,
        String fingerprint,
        String affectedUser,
        String sourceIp,
        String assignee,
        JsonNode evidence,
        int detectionCount,
        String resolution,
        String createdBy,
        Instant detectedAt,
        Instant createdAt,
        Instant updatedAt,
        Instant acknowledgedAt,
        Instant resolvedAt,
        List<Note> notes,
        List<History> history) {

    public record Note(Long id, String author, String content, Instant createdAt) {
        static Note from(IncidentNote n) {
            return new Note(n.getId(), n.getAuthor(), n.getContent(), n.getCreatedAt());
        }
    }

    public record History(Long id, String action, String fromValue, String toValue, String actor, Instant timestamp) {
        static History from(IncidentHistory h) {
            return new History(h.getId(), h.getAction().name(), h.getFromValue(), h.getToValue(), h.getActor(),
                    h.getTimestamp());
        }
    }

    public static IncidentDetail from(Incident i, JsonNode evidence) {
        return new IncidentDetail(i.getId(), i.getTitle(), i.getDescription(), i.getSeverity(), i.getStatus(),
                i.getStatus().allowedTransitions(), i.getSource(), i.getRuleId(), i.getFingerprint(),
                i.getAffectedUser(), i.getSourceIp(), i.getAssignee(), evidence, i.getDetectionCount(),
                i.getResolution(), i.getCreatedBy(), i.getDetectedAt(), i.getCreatedAt(), i.getUpdatedAt(),
                i.getAcknowledgedAt(), i.getResolvedAt(),
                i.getNotes().stream().map(Note::from).toList(),
                i.getHistory().stream().map(History::from).toList());
    }
}
