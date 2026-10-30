package com.minisoc.incidents.dto;

import com.minisoc.incidents.domain.IncidentStatus;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * @param resolution required when moving to RESOLVED or FALSE_POSITIVE
 * @param comment    optional free text, recorded as an investigation note
 */
public record StatusUpdateRequest(
        @NotNull IncidentStatus status,
        @Size(max = 10_000) String resolution,
        @Size(max = 10_000) String comment) {
}
