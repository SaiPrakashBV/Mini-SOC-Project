package com.minisoc.incidents.dto;

import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;

import java.time.Instant;
import java.util.List;

/** Query parameters accepted by GET /api/incidents. All fields are optional. */
public record IncidentFilter(
        List<IncidentStatus> status,
        List<Severity> severity,
        String assignee,
        String affectedUser,
        String sourceIp,
        String ruleId,
        String q,
        Instant from,
        Instant to) {
}
