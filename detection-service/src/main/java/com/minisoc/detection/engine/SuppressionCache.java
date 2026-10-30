package com.minisoc.detection.engine;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Prevents the same rule/entity pair from firing on every poll while an attack is
 * still inside the rule window. After the suppression period it may fire again,
 * which the incident tracker records as a re-trigger of the open incident.
 */
@Component
public class SuppressionCache {

    private final Map<String, Instant> suppressedUntil = new ConcurrentHashMap<>();

    /** Returns true and starts suppression if the key is not currently suppressed. */
    public boolean tryAcquire(String key, Duration suppressFor, Instant now) {
        purge(now);
        Instant until = suppressedUntil.get(key);
        if (until != null && until.isAfter(now)) return false;
        suppressedUntil.put(key, now.plus(suppressFor));
        return true;
    }

    private void purge(Instant now) {
        suppressedUntil.entrySet().removeIf(e -> e.getValue().isBefore(now));
    }
}
