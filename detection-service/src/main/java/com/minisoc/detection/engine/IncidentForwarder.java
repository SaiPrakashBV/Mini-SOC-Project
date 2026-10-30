package com.minisoc.detection.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.detection.config.DetectionProperties;
import com.minisoc.detection.rules.DetectionAlert;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Opens (or re-triggers) an incident in the incident tracker for a fired alert. */
@Component
public class IncidentForwarder {

    private final RestClient tracker;
    private final boolean enabled;

    public IncidentForwarder(RestClient trackerClient, DetectionProperties props) {
        this.tracker = trackerClient;
        this.enabled = props.tracker().enabled();
    }

    /** @return the incident id, or empty when forwarding is disabled */
    public Optional<Long> forward(DetectionAlert alert) {
        if (!enabled) return Optional.empty();
        JsonNode response = tracker.post()
                .uri("/api/incidents")
                .contentType(MediaType.APPLICATION_JSON)
                .body(toIncident(alert))
                .retrieve()
                .body(JsonNode.class);
        return Optional.ofNullable(response).map(r -> r.path("id").asLong());
    }

    static Map<String, Object> toIncident(DetectionAlert a) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("title", truncate(a.title(), 200));
        body.put("description", """
                %s

                Rule %s fired: %d matching events for %s=%s between %s and %s (threshold %d in %s).%s"""
                .formatted(a.description() == null ? a.ruleName() : a.description(),
                        a.ruleId(), a.count(), a.groupBy(), a.entity(), a.firstSeen(), a.lastSeen(),
                        a.threshold(), a.window(),
                        a.mitre() == null ? "" : "\nMITRE ATT&CK: " + a.mitre()));
        if (a.distinctCount() != null) {
            body.put("description", body.get("description") + "\nDistinct values: " + a.distinctCount());
        }
        body.put("severity", a.severity().name());
        body.put("ruleId", a.ruleId());
        body.put("fingerprint", a.fingerprint());
        body.put("affectedUser", "username".equals(a.groupBy()) ? a.entity() : firstRealUser(a));
        body.put("sourceIp", "source_ip".equals(a.groupBy()) ? a.entity()
                : a.sourceIps().isEmpty() ? null : a.sourceIps().getFirst());
        body.put("detectedAt", a.firstSeen() != null ? a.firstSeen().toString() : a.timestamp().toString());
        Map<String, Object> evidence = new LinkedHashMap<>(Map.of(
                "alertId", a.alertId(),
                "count", a.count(),
                "threshold", a.threshold(),
                "window", a.window(),
                "sourceIps", a.sourceIps(),
                "usernames", a.usernames(),
                "paths", a.paths(),
                "samples", a.samples()));
        if (a.distinctCount() != null) evidence.put("distinctCount", a.distinctCount());
        body.put("evidence", evidence);
        return body;
    }

    private static String firstRealUser(DetectionAlert a) {
        return a.usernames().stream().filter(u -> !"anonymous".equals(u)).findFirst().orElse(null);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 3) + "...";
    }
}
