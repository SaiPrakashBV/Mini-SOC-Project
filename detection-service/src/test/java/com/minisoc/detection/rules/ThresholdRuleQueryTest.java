package com.minisoc.detection.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ThresholdRuleQueryTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private final RuleDefinition bruteForce = new RuleDefinition("BRUTE_FORCE_LOGIN", "Potential brute-force login",
            null, Severity.HIGH, Duration.ofMinutes(2), 5, "username",
            Map.of("event_type", List.of("LOGIN_FAILURE")), null, null, 20, Severity.CRITICAL, null, "T1110", null, null, null, null);

    @Test
    void buildsWindowedTermsAggregation() {
        Instant now = Instant.parse("2026-10-30T12:00:00Z");
        JsonNode q = mapper.valueToTree(ThresholdRuleQuery.build(bruteForce, now));

        assertThat(q.at("/size").asInt()).isZero();
        assertThat(q.at("/query/bool/filter/0/range/@timestamp/gte").asText()).isEqualTo("2026-10-30T11:58:00Z");
        assertThat(q.at("/query/bool/filter/1/terms/event_type/0").asText()).isEqualTo("LOGIN_FAILURE");
        assertThat(q.at("/aggs/by_entity/terms/field").asText()).isEqualTo("username");
        assertThat(q.at("/aggs/by_entity/terms/min_doc_count").asInt()).isEqualTo(5);
    }

    @Test
    void parsesBucketsIntoAlertsAndEscalates() throws Exception {
        String response = """
                {"aggregations":{"by_entity":{"buckets":[
                  {"key":"alice","doc_count":6,
                   "first_seen":{"value":1.0,"value_as_string":"2026-10-30T11:58:10.000Z"},
                   "last_seen":{"value":2.0,"value_as_string":"2026-10-30T11:59:50.000Z"},
                   "source_ips":{"buckets":[{"key":"203.0.113.7","doc_count":6}]},
                   "usernames":{"buckets":[{"key":"alice","doc_count":6}]},
                   "paths":{"buckets":[]},
                   "samples":{"hits":{"hits":[{"_source":{"event_type":"LOGIN_FAILURE","http_status":401}}]}}},
                  {"key":"bob","doc_count":25,"source_ips":{"buckets":[]},"usernames":{"buckets":[]},
                   "paths":{"buckets":[]},"samples":{"hits":{"hits":[]}}}
                ]}}}
                """;
        var alerts = ThresholdRuleQuery.parse(bruteForce, mapper.readTree(response), Instant.now());

        assertThat(alerts).hasSize(2);
        var alice = alerts.getFirst();
        assertThat(alice.entity()).isEqualTo("alice");
        assertThat(alice.severity()).isEqualTo(Severity.HIGH);
        assertThat(alice.sourceIps()).containsExactly("203.0.113.7");
        assertThat(alice.firstSeen()).isEqualTo(Instant.parse("2026-10-30T11:58:10Z"));
        assertThat(alice.fingerprint()).isEqualTo("BRUTE_FORCE_LOGIN:username:alice");
        assertThat(alice.samples().getFirst()).containsEntry("http_status", 401);
        assertThat(alerts.get(1).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void distinctConditionFiltersBuckets() throws Exception {
        var distributed = new RuleDefinition("DISTRIBUTED_BRUTE_FORCE", "Distributed brute force", null,
                Severity.HIGH, Duration.ofMinutes(10), 5, "username",
                Map.of("event_type", List.of("LOGIN_FAILURE")), null, null, null, null, null, null, null,
                null, "source_ip", 5);
        JsonNode q = mapper.valueToTree(ThresholdRuleQuery.build(distributed, Instant.now()));
        assertThat(q.at("/aggs/by_entity/aggs/distinct/cardinality/field").asText()).isEqualTo("source_ip");

        String response = """
                {"aggregations":{"by_entity":{"buckets":[
                  {"key":"admin","doc_count":6,"distinct":{"value":6}},
                  {"key":"alice","doc_count":9,"distinct":{"value":1}}
                ]}}}
                """;
        var alerts = ThresholdRuleQuery.parse(distributed, mapper.readTree(response), Instant.now());
        assertThat(alerts).extracting(DetectionAlert::entity).containsExactly("admin");
        assertThat(alerts.getFirst().distinctCount()).isEqualTo(6L);
    }

    @Test
    void requireConditionNeedsAMatchingEvent() throws Exception {
        var takeover = new RuleDefinition("ACCOUNT_TAKEOVER", "Account takeover", null, Severity.CRITICAL,
                Duration.ofMinutes(10), 5, "source_ip",
                Map.of("event_type", List.of("LOGIN_FAILURE")), null, null, null, null, null,
                null, null, Map.of("event_type", List.of("LOGIN_SUCCESS")), null, null);
        JsonNode q = mapper.valueToTree(ThresholdRuleQuery.build(takeover, Instant.now()));
        assertThat(q.at("/aggs/by_entity/aggs/required/filter/bool/filter/0/terms/event_type/0").asText())
                .isEqualTo("LOGIN_SUCCESS");
        assertThat(q.at("/aggs/by_entity/aggs/matched/filter/bool/filter/0/terms/event_type/0").asText())
                .isEqualTo("LOGIN_FAILURE");
        assertThat(q.at("/query/bool/minimum_should_match").asInt()).isEqualTo(1);
        assertThat(q.at("/aggs/by_entity/terms/min_doc_count").asInt()).isEqualTo(1);

        String response = """
                {"aggregations":{"by_entity":{"buckets":[
                  {"key":"45.155.205.233","doc_count":7,"matched":{"doc_count":6},"required":{"doc_count":1}},
                  {"key":"203.0.113.66","doc_count":6,"matched":{"doc_count":6},"required":{"doc_count":0}},
                  {"key":"10.0.0.11","doc_count":9,"matched":{"doc_count":0},"required":{"doc_count":9}}
                ]}}}
                """;
        var alerts = ThresholdRuleQuery.parse(takeover, mapper.readTree(response), Instant.now());
        assertThat(alerts).extracting(DetectionAlert::entity).containsExactly("45.155.205.233");
        assertThat(alerts.getFirst().count()).isEqualTo(6);
        assertThat(alerts.getFirst().distinctCount()).isNull();
    }

    @Test
    void humanizesWindows() {
        assertThat(ThresholdRuleQuery.humanize(Duration.ofMinutes(2))).isEqualTo("2m");
        assertThat(ThresholdRuleQuery.humanize(Duration.ofHours(1))).isEqualTo("1h");
        assertThat(ThresholdRuleQuery.humanize(Duration.ofSeconds(45))).isEqualTo("45s");
    }
}
