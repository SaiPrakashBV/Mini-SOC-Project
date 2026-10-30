package com.minisoc.detection.config;

import com.minisoc.detection.rules.RuleDefinition;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@ConfigurationProperties(prefix = "detection")
public record DetectionProperties(
        @Valid OpenSearch opensearch,
        @Valid Tracker tracker,
        List<@Valid RuleDefinition> rules) {

    public DetectionProperties {
        if (rules == null) rules = List.of();
    }

    /**
     * @param eventIndex pattern of the indices Fluent Bit writes security events to
     * @param alertIndex index where the detection service persists fired alerts
     */
    public record OpenSearch(@NotBlank String url, String username, String password,
                             @NotBlank String eventIndex, @NotBlank String alertIndex) {
    }

    public record Tracker(@NotBlank String url, @NotBlank String apiKey, boolean enabled) {
    }
}
