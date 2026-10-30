package com.minisoc.detection.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.minisoc.detection.config.DetectionProperties;
import com.minisoc.detection.opensearch.OpenSearchClient;
import com.minisoc.detection.rules.DetectionAlert;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Persists alerts in OpenSearch so they survive restarts and can be explored in OpenSearch Dashboards. */
@Component
public class AlertStore {

    private final OpenSearchClient client;
    private final String index;

    public AlertStore(OpenSearchClient client, DetectionProperties props) {
        this.client = client;
        this.index = props.opensearch().alertIndex();
    }

    public void save(DetectionAlert alert) {
        client.index(index, alert.alertId(), alert);
    }

    public void linkIncident(String alertId, long incidentId) {
        client.update(index, alertId, Map.of("incidentId", incidentId));
    }

    public List<JsonNode> recent(int size, String severity, String ruleId) {
        List<Object> filters = new ArrayList<>();
        if (severity != null) filters.add(Map.of("term", Map.of("severity", severity)));
        if (ruleId != null) filters.add(Map.of("term", Map.of("ruleId", ruleId)));
        var body = Map.of(
                "size", size,
                "sort", List.of(Map.of("@timestamp", Map.of("order", "desc"))),
                "query", Map.of("bool", Map.of("filter", filters)));
        List<JsonNode> out = new ArrayList<>();
        client.search(index, body).path("hits").path("hits").forEach(h -> out.add(h.path("_source")));
        return out;
    }

    public JsonNode summary(String since) {
        var body = Map.of(
                "size", 0,
                "query", Map.of("range", Map.of("@timestamp", Map.of("gte", since))),
                "aggs", Map.of(
                        "by_severity", Map.of("terms", Map.of("field", "severity", "size", 10)),
                        "by_rule", Map.of("terms", Map.of("field", "ruleId", "size", 20)),
                        "over_time", Map.of("date_histogram", Map.of(
                                "field", "@timestamp", "fixed_interval", "1h", "min_doc_count", 0))));
        return client.search(index, body);
    }
}
