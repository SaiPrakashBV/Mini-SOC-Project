package com.minisoc.target.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/**
 * Security settings bound from {@code app.security.*}. Secrets come from environment
 * variables (see .env.example) and are never committed.
 */
@Validated
@ConfigurationProperties(prefix = "app.security")
public record AppSecurityProperties(
        @NotBlank @Size(min = 32, message = "JWT secret must be at least 32 characters") String jwtSecret,
        Duration jwtTtl,
        String jwtIssuer,
        boolean trustForwardedFor,
        List<DemoUser> users) {

    public AppSecurityProperties {
        if (jwtTtl == null) jwtTtl = Duration.ofMinutes(30);
        if (jwtIssuer == null) jwtIssuer = "mini-soc-target-app";
        if (users == null) users = List.of();
    }

    public record DemoUser(String username, String password, List<String> roles, String email) {
    }
}
