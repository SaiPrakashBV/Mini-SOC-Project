package com.minisoc.incidents.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * @param serviceApiKey shared secret the detection service sends in X-API-Key
 * @param analysts      SOC analyst accounts (HTTP Basic) used by the dashboard
 */
@Validated
@ConfigurationProperties(prefix = "app.security")
public record TrackerSecurityProperties(
        @NotBlank @Size(min = 16) String serviceApiKey,
        List<Analyst> analysts) {

    public TrackerSecurityProperties {
        if (analysts == null) analysts = List.of();
    }

    public record Analyst(String username, String password, String displayName, List<String> roles) {
    }
}
