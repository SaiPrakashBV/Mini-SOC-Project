package com.minisoc.incidents.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.incidents.domain.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public record CreateIncidentRequest(
        @NotBlank @Size(max = 200) String title,
        @Size(max = 10_000) String description,
        @NotNull Severity severity,
        @Size(max = 64) String ruleId,
        @Size(max = 200) String fingerprint,
        @Size(max = 100) String affectedUser,
        @Size(max = 64) String sourceIp,
        JsonNode evidence,
        Instant detectedAt) {
}
