package com.minisoc.detection.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.detection.config.DetectionProperties;
import com.minisoc.detection.engine.AlertStore;
import com.minisoc.detection.engine.DetectionEngine;
import com.minisoc.detection.opensearch.OpenSearchClient;
import com.minisoc.detection.rules.DetectionAlert;
import com.minisoc.detection.rules.RuleDefinition;
import com.minisoc.detection.rules.Severity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DetectionController {

    private final AlertStore alerts;
    private final DetectionEngine engine;
    private final DetectionProperties props;
    private final EventQueryService events;
    private final OpenSearchClient openSearch;

    public DetectionController(AlertStore alerts, DetectionEngine engine, DetectionProperties props,
                               EventQueryService events, OpenSearchClient openSearch) {
        this.alerts = alerts;
        this.engine = engine;
        this.props = props;
        this.events = events;
        this.openSearch = openSearch;
    }

    @GetMapping("/alerts")
    public List<JsonNode> alerts(@RequestParam(defaultValue = "50") int size,
                                 @RequestParam(required = false) Severity severity,
                                 @RequestParam(required = false) String ruleId) {
        return alerts.recent(Math.clamp(size, 1, 500), severity == null ? null : severity.name(), ruleId);
    }

    @GetMapping("/alerts/summary")
    public Map<String, Object> alertSummary(@RequestParam(defaultValue = "24") int hours) {
        JsonNode aggs = alerts.summary("now-" + Math.clamp(hours, 1, 720) + "h").path("aggregations");
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (Severity s : Severity.values()) bySeverity.put(s.name(), 0L);
        aggs.path("by_severity").path("buckets")
                .forEach(b -> bySeverity.put(b.path("key").asText(), b.path("doc_count").asLong()));
        Map<String, Long> byRule = new LinkedHashMap<>();
        aggs.path("by_rule").path("buckets")
                .forEach(b -> byRule.put(b.path("key").asText(), b.path("doc_count").asLong()));
        return Map.of("hours", hours, "bySeverity", bySeverity, "byRule", byRule,
                "total", bySeverity.values().stream().mapToLong(Long::longValue).sum());
    }

    @GetMapping("/rules")
    public List<Map<String, Object>> rules() {
        var status = engine.ruleStatus();
        return props.rules().stream().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("rule", r);
            m.put("status", status.get(r.id()));
            return m;
        }).toList();
    }

    /** Runs all rules immediately (handy for demos instead of waiting for the next poll). */
    @PostMapping("/rules/run")
    public Map<String, Object> runNow() {
        List<DetectionAlert> fired = engine.runOnce();
        return Map.of("fired", fired.size(), "alerts", fired);
    }

    @GetMapping("/events/recent")
    public List<JsonNode> recentEvents(@RequestParam(defaultValue = "50") int size,
                                       @RequestParam(defaultValue = "60") int minutes) {
        return events.recentSuspicious(Math.clamp(size, 1, 500), Math.clamp(minutes, 1, 10080));
    }

    @GetMapping("/events/timeline")
    public List<JsonNode> timeline(@RequestParam(required = false) String username,
                                   @RequestParam(required = false) String sourceIp,
                                   @RequestParam(required = false) String correlationId,
                                   @RequestParam(defaultValue = "1440") int minutes,
                                   @RequestParam(defaultValue = "200") int size) {
        if (username == null && sourceIp == null && correlationId == null) {
            throw new IllegalArgumentException("Provide username, sourceIp or correlationId");
        }
        return events.timeline(username, sourceIp, correlationId, Math.clamp(minutes, 1, 10080),
                Math.clamp(size, 1, 1000));
    }

    @GetMapping("/events/activity")
    public Map<String, Object> activity(@RequestParam(defaultValue = "60") int minutes) {
        return events.activity(Math.clamp(minutes, 5, 10080));
    }

    @GetMapping("/health/pipeline")
    public Map<String, Object> pipeline() {
        return Map.of("opensearch", openSearch.ping() ? "UP" : "DOWN",
                "pendingIncidentForwards", engine.pendingForwardCount());
    }
}
