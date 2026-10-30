package com.minisoc.detection.rules;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Builds the OpenSearch aggregation query for a rule and turns the response into alerts. */
public final class ThresholdRuleQuery {

    static final String TIMESTAMP = "@timestamp";
    private static final int MAX_ENTITIES = 100;

    private ThresholdRuleQuery() {
    }

    public static Map<String, Object> build(RuleDefinition rule, Instant now) {
        List<Object> filters = new ArrayList<>();
        filters.add(Map.of("range", Map.of(TIMESTAMP, Map.of(
                "gte", now.minus(rule.window()).toString(),
                "lte", now.toString()))));
        List<Object> matchClauses = termsClauses(rule.match());
        List<Object> requireClauses = termsClauses(rule.require());
        boolean hasRequire = !requireClauses.isEmpty();
        if (!hasRequire) filters.addAll(matchClauses);
        if (rule.pathPrefix() != null && !rule.pathPrefix().isBlank()) {
            filters.add(Map.of("prefix", Map.of("http_path", rule.pathPrefix())));
        }
        List<Object> mustNot = new ArrayList<>();
        rule.exclude().forEach((field, values) -> mustNot.add(Map.of("terms", Map.of(field, values))));

        Map<String, Object> subAggs = new LinkedHashMap<>();
        subAggs.put("first_seen", Map.of("min", Map.of("field", TIMESTAMP)));
        subAggs.put("last_seen", Map.of("max", Map.of("field", TIMESTAMP)));
        subAggs.put("source_ips", Map.of("terms", Map.of("field", "source_ip", "size", 10)));
        subAggs.put("usernames", Map.of("terms", Map.of("field", "username", "size", 10)));
        subAggs.put("paths", Map.of("terms", Map.of("field", "http_path", "size", 10)));
        subAggs.put("samples", Map.of("top_hits", Map.of(
                "size", 5,
                "sort", List.of(Map.of(TIMESTAMP, Map.of("order", "desc"))),
                "_source", List.of(TIMESTAMP, "event_type", "message", "username", "source_ip", "http_method",
                        "http_path", "http_status", "correlation_id", "reason", "attack_type", "attack_sample"))));
        if (rule.hasDistinctCondition()) {
            subAggs.put("distinct", Map.of("cardinality", Map.of("field", rule.distinctField())));
        }

        Map<String, Object> bool = new LinkedHashMap<>();
        bool.put("filter", filters);
        bool.put("must_not", mustNot);
        Map<String, Object> terms = new LinkedHashMap<>();
        terms.put("field", rule.groupBy());
        terms.put("size", MAX_ENTITIES);
        if (hasRequire) {
            // Fetch events matching either side, then count them separately per entity:
            // the threshold applies to "matched" only, and "required" must be >= 1.
            bool.put("should", List.of(
                    Map.of("bool", Map.of("filter", matchClauses)),
                    Map.of("bool", Map.of("filter", requireClauses))));
            bool.put("minimum_should_match", 1);
            subAggs.put("matched", Map.of("filter", Map.of("bool", Map.of("filter", matchClauses))));
            subAggs.put("required", Map.of("filter", Map.of("bool", Map.of("filter", requireClauses))));
            terms.put("min_doc_count", 1);
            terms.put("order", Map.of("matched", "desc"));
        } else {
            terms.put("min_doc_count", rule.threshold());
            terms.put("order", Map.of("_count", "desc"));
        }

        return Map.of(
                "size", 0,
                "track_total_hits", false,
                "query", Map.of("bool", bool),
                "aggs", Map.of("by_entity", Map.of("terms", terms, "aggs", subAggs)));
    }

    private static List<Object> termsClauses(Map<String, List<String>> fieldValues) {
        List<Object> clauses = new ArrayList<>();
        fieldValues.forEach((field, values) -> clauses.add(Map.of("terms", Map.of(field, values))));
        return clauses;
    }

    public static List<DetectionAlert> parse(RuleDefinition rule, JsonNode response, Instant now) {
        List<DetectionAlert> alerts = new ArrayList<>();
        JsonNode buckets = response.path("aggregations").path("by_entity").path("buckets");
        for (JsonNode bucket : buckets) {
            boolean hasRequire = !rule.require().isEmpty();
            long count = hasRequire ? bucket.path("matched").path("doc_count").asLong()
                    : bucket.path("doc_count").asLong();
            if (count < rule.threshold()) continue;
            Long distinct = null;
            if (rule.hasDistinctCondition()) {
                distinct = bucket.path("distinct").path("value").asLong();
                if (distinct < rule.minDistinct()) continue;
            }
            if (hasRequire && bucket.path("required").path("doc_count").asLong() == 0) continue;
            alerts.add(new DetectionAlert(
                    UUID.randomUUID().toString(),
                    now,
                    rule.id(),
                    rule.name(),
                    rule.description(),
                    rule.severityFor(count),
                    rule.mitre(),
                    rule.groupBy(),
                    bucket.path("key").asText(),
                    count,
                    distinct,
                    rule.threshold(),
                    humanize(rule.window()),
                    instant(bucket.path("first_seen")),
                    instant(bucket.path("last_seen")),
                    keys(bucket.path("source_ips")),
                    keys(bucket.path("usernames")),
                    keys(bucket.path("paths")),
                    samples(bucket.path("samples")),
                    null));
        }
        return alerts;
    }

    private static Instant instant(JsonNode agg) {
        String s = agg.path("value_as_string").asText(null);
        if (s != null) return Instant.parse(s);
        JsonNode v = agg.path("value");
        return v.isNumber() ? Instant.ofEpochMilli(v.asLong()) : null;
    }

    private static List<String> keys(JsonNode termsAgg) {
        List<String> out = new ArrayList<>();
        termsAgg.path("buckets").forEach(b -> out.add(b.path("key").asText()));
        return out;
    }

    private static List<Map<String, Object>> samples(JsonNode topHits) {
        List<Map<String, Object>> out = new ArrayList<>();
        topHits.path("hits").path("hits").forEach(h -> {
            Map<String, Object> src = new LinkedHashMap<>();
            h.path("_source").fields().forEachRemaining(e -> src.put(e.getKey(),
                    e.getValue().isNumber() ? e.getValue().numberValue() : e.getValue().asText()));
            out.add(src);
        });
        return out;
    }

    static String humanize(java.time.Duration d) {
        long s = d.toSeconds();
        if (s % 3600 == 0) return (s / 3600) + "h";
        if (s % 60 == 0) return (s / 60) + "m";
        return s + "s";
    }
}
