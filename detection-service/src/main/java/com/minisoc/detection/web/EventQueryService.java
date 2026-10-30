package com.minisoc.detection.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.detection.config.DetectionProperties;
import com.minisoc.detection.opensearch.OpenSearchClient;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Read-only queries over raw security events for the dashboard. */
@Service
public class EventQueryService {

    /** Events worth an analyst's attention: failures and every authorization problem. */
    private static final List<String> SUSPICIOUS_TYPES = List.of(
            "LOGIN_FAILURE", "UNAUTHORIZED", "ACCESS_DENIED", "TOKEN_INVALID", "RESOURCE_OWNERSHIP_VIOLATION");

    private final OpenSearchClient client;
    private final String index;

    public EventQueryService(OpenSearchClient client, DetectionProperties props) {
        this.client = client;
        this.index = props.opensearch().eventIndex();
    }

    public List<JsonNode> recentSuspicious(int size, int minutes) {
        var body = Map.of(
                "size", size,
                "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                "query", Map.of("bool", Map.of("filter", List.of(
                        Map.of("range", Map.of("@timestamp", Map.of("gte", "now-" + minutes + "m"))),
                        Map.of("terms", Map.of("event_type", SUSPICIOUS_TYPES))))));
        return hits(client.search(index, body));
    }

    /** Chronological events for one entity - the "event timeline" an analyst investigates. */
    public List<JsonNode> timeline(String username, String sourceIp, String correlationId, int minutes, int size) {
        List<Object> filters = new ArrayList<>();
        filters.add(Map.of("range", Map.of("@timestamp", Map.of("gte", "now-" + minutes + "m"))));
        filters.add(Map.of("exists", Map.of("field", "event_type")));
        if (username != null) filters.add(Map.of("term", Map.of("username", username)));
        if (sourceIp != null) filters.add(Map.of("term", Map.of("source_ip", sourceIp)));
        if (correlationId != null) filters.add(Map.of("term", Map.of("correlation_id", correlationId)));
        var body = Map.of(
                "size", size,
                "sort", List.of(Map.of("@timestamp", Map.of("order", "asc"))),
                "query", Map.of("bool", Map.of("filter", filters)));
        return hits(client.search(index, body));
    }

    /** Per-minute counts of suspicious event types, plus top affected users / IPs. */
    public Map<String, Object> activity(int minutes) {
        String interval = minutes <= 120 ? "1m" : minutes <= 1440 ? "10m" : "1h";
        var body = Map.of(
                "size", 0,
                "query", Map.of("bool", Map.of("filter", List.of(
                        Map.of("range", Map.of("@timestamp", Map.of("gte", "now-" + minutes + "m")))))),
                "aggs", Map.of(
                        "over_time", Map.of(
                                "date_histogram", Map.of("field", "@timestamp", "fixed_interval", interval,
                                        "min_doc_count", 0,
                                        "extended_bounds", Map.of("min", "now-" + minutes + "m", "max", "now")),
                                "aggs", Map.of("types", Map.of("terms", Map.of(
                                        "field", "event_type", "include", SUSPICIOUS_TYPES, "size", 10)))),
                        "by_type", Map.of("terms", Map.of("field", "event_type", "size", 20)),
                        "suspicious", Map.of(
                                "filter", Map.of("terms", Map.of("event_type", SUSPICIOUS_TYPES)),
                                "aggs", Map.of(
                                        "users", Map.of("terms", Map.of("field", "username", "size", 10)),
                                        "ips", Map.of("terms", Map.of("field", "source_ip", "size", 10)))),
                        "status_codes", Map.of("terms", Map.of("field", "http_status", "size", 20))));
        JsonNode aggs = client.search(index, body).path("aggregations");

        List<Map<String, Object>> series = new ArrayList<>();
        aggs.path("over_time").path("buckets").forEach(b -> {
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("time", b.path("key_as_string").asText());
            point.put("total", b.path("doc_count").asLong());
            b.path("types").path("buckets").forEach(t -> point.put(t.path("key").asText(), t.path("doc_count").asLong()));
            series.add(point);
        });
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("interval", interval);
        result.put("series", series);
        result.put("byEventType", buckets(aggs.path("by_type")));
        result.put("topUsers", buckets(aggs.path("suspicious").path("users")));
        result.put("topSourceIps", buckets(aggs.path("suspicious").path("ips")));
        result.put("statusCodes", buckets(aggs.path("status_codes")));
        return result;
    }

    private static List<Map<String, Object>> buckets(JsonNode terms) {
        List<Map<String, Object>> out = new ArrayList<>();
        terms.path("buckets").forEach(b -> out.add(Map.of("key", b.path("key").asText(), "count", b.path("doc_count").asLong())));
        return out;
    }

    private static List<JsonNode> hits(JsonNode response) {
        List<JsonNode> out = new ArrayList<>();
        response.path("hits").path("hits").forEach(h -> out.add(h.path("_source")));
        return out;
    }
}
