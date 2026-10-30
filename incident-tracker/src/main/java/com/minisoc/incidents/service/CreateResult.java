package com.minisoc.incidents.service;

import com.minisoc.incidents.dto.IncidentDetail;

/** @param deduplicated true when an existing active incident absorbed the new detection */
public record CreateResult(IncidentDetail incident, boolean deduplicated) {
}
