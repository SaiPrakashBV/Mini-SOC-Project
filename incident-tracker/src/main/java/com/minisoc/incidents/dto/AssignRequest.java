package com.minisoc.incidents.dto;

import jakarta.validation.constraints.Size;

/** A null or blank assignee un-assigns the incident. */
public record AssignRequest(@Size(max = 100) String assignee) {
}
