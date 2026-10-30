package com.minisoc.target.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static net.logstash.logback.argument.StructuredArguments.entries;

/**
 * Writes security audit events as structured JSON. Every event carries
 * {@code event_type}, {@code event_category}, {@code outcome} plus the request
 * context (correlation id, source ip, username) taken from the MDC.
 */
@Component
public class SecurityEventLogger {

    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");

    public void success(SecurityEventType type, String message, Map<String, ?> details) {
        emit(type, "SUCCESS", message, details);
    }

    public void failure(SecurityEventType type, String message, Map<String, ?> details) {
        emit(type, "FAILURE", message, details);
    }

    public void emit(SecurityEventType type, String outcome, String message, Map<String, ?> details) {
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("event_type", type.name());
        fields.put("event_category", type.category());
        fields.put("outcome", outcome);
        fields.put("log_type", "security_audit");
        if (details != null) {
            details.forEach((k, v) -> {
                if (v != null) fields.put(k, v);
            });
        }
        // correlation_id and source_ip come from the MDC via the encoder. username is
        // excluded from the MDC output (see logback-spring.xml) and always written here,
        // so events that name a user explicitly (e.g. a failed login) win over the MDC.
        if (!fields.containsKey("username")) {
            String mdcUser = MDC.get(RequestContext.MDC_USERNAME);
            fields.put("username", mdcUser != null ? mdcUser : "anonymous");
        }
        List<Object> args = new ArrayList<>();
        args.add(entries(fields));
        if ("FAILURE".equals(outcome)) {
            AUDIT.warn(message, args.toArray());
        } else {
            AUDIT.info(message, args.toArray());
        }
    }
}
