package com.minisoc.incidents.dto;

import com.minisoc.incidents.domain.Severity;
import jakarta.validation.constraints.NotNull;

public record SeverityUpdateRequest(@NotNull Severity severity) {
}
