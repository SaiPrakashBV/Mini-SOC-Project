package com.minisoc.detection.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/** Analyst accounts allowed to read alerts/events (same credentials as the incident tracker). */
@ConfigurationProperties(prefix = "app.security")
public record AnalystProperties(List<Analyst> analysts) {

    public AnalystProperties {
        if (analysts == null) analysts = List.of();
    }

    public record Analyst(String username, String password) {
    }
}
