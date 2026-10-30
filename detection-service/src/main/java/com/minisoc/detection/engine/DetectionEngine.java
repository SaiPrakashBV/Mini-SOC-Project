package com.minisoc.detection.engine;

import com.minisoc.detection.config.DetectionProperties;
import com.minisoc.detection.opensearch.OpenSearchClient;
import com.minisoc.detection.rules.DetectionAlert;
import com.minisoc.detection.rules.RuleDefinition;
import com.minisoc.detection.rules.ThresholdRuleQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Periodically evaluates every enabled rule against the security event index,
 * persists fired alerts and forwards them to the incident tracker. Alerts that
 * could not be forwarded (tracker down) are retried on the next cycle.
 */
@Service
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    private final OpenSearchClient openSearch;
    private final DetectionProperties props;
    private final SuppressionCache suppression;
    private final AlertStore alerts;
    private final IncidentForwarder forwarder;
    private final Queue<DetectionAlert> pendingForward = new ConcurrentLinkedQueue<>();
    private final Map<String, RuleStatus> ruleStatus = new ConcurrentHashMap<>();

    public DetectionEngine(OpenSearchClient openSearch, DetectionProperties props, SuppressionCache suppression,
                           AlertStore alerts, IncidentForwarder forwarder) {
        this.openSearch = openSearch;
        this.props = props;
        this.suppression = suppression;
        this.alerts = alerts;
        this.forwarder = forwarder;
    }

    public record RuleStatus(Instant lastRun, int lastMatches, long totalFired, String lastError) {
    }

    @Scheduled(fixedDelayString = "${detection.poll-interval:PT15S}", initialDelayString = "${detection.initial-delay:PT20S}")
    public void scheduledRun() {
        runOnce();
    }

    /** Evaluates all rules once. Synchronized so a manual run never overlaps the scheduled one. */
    public synchronized List<DetectionAlert> runOnce() {
        retryPending();
        Instant now = Instant.now();
        List<DetectionAlert> fired = new ArrayList<>();
        for (RuleDefinition rule : props.rules()) {
            if (!rule.enabled()) continue;
            RuleStatus previous = ruleStatus.getOrDefault(rule.id(), new RuleStatus(null, 0, 0, null));
            try {
                var response = openSearch.search(props.opensearch().eventIndex(), ThresholdRuleQuery.build(rule, now));
                List<DetectionAlert> matches = ThresholdRuleQuery.parse(rule, response, now);
                int newAlerts = 0;
                for (DetectionAlert alert : matches) {
                    if (!suppression.tryAcquire(alert.fingerprint(), rule.suppress(), now)) continue;
                    handle(alert);
                    fired.add(alert);
                    newAlerts++;
                }
                ruleStatus.put(rule.id(), new RuleStatus(now, matches.size(), previous.totalFired() + newAlerts, null));
            } catch (Exception e) {
                log.warn("Rule {} failed: {}", rule.id(), e.getMessage());
                ruleStatus.put(rule.id(), new RuleStatus(now, 0, previous.totalFired(), e.getMessage()));
            }
        }
        return fired;
    }

    private void handle(DetectionAlert alert) {
        log.warn("ALERT [{}] {} -> {}", alert.severity(), alert.ruleId(), alert.title());
        try {
            alerts.save(alert);
        } catch (Exception e) {
            log.error("Could not persist alert {}: {}", alert.alertId(), e.getMessage());
        }
        forward(alert);
    }

    private void forward(DetectionAlert alert) {
        try {
            forwarder.forward(alert).ifPresent(id -> {
                log.info("Alert {} linked to incident {}", alert.alertId(), id);
                try {
                    alerts.linkIncident(alert.alertId(), id);
                } catch (Exception e) {
                    log.warn("Could not link alert {} to incident {}: {}", alert.alertId(), id, e.getMessage());
                }
            });
        } catch (Exception e) {
            log.warn("Incident tracker unavailable ({}); will retry alert {}", e.getMessage(), alert.alertId());
            pendingForward.add(alert);
        }
    }

    private void retryPending() {
        int n = pendingForward.size();
        for (int i = 0; i < n; i++) {
            DetectionAlert alert = pendingForward.poll();
            if (alert != null) forward(alert);
        }
    }

    public Map<String, RuleStatus> ruleStatus() {
        return Map.copyOf(ruleStatus);
    }

    public int pendingForwardCount() {
        return pendingForward.size();
    }
}
