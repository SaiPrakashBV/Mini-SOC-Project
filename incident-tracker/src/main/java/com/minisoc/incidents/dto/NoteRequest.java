package com.minisoc.incidents.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record NoteRequest(@NotBlank @Size(max = 10_000) String content) {
}
