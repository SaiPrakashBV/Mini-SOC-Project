package com.minisoc.target.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Outermost filter (runs before Spring Security). Establishes the correlation id and
 * source IP for the request and writes one HTTP_REQUEST access event when it completes.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]{8,64}$");

    private final SecurityEventLogger events;
    private final ClientIpResolver ipResolver;

    public RequestLoggingFilter(SecurityEventLogger events, ClientIpResolver ipResolver) {
        this.events = events;
        this.ipResolver = ipResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long start = System.nanoTime();
        String correlationId = request.getHeader(RequestContext.CORRELATION_HEADER);
        if (correlationId == null || !SAFE_ID.matcher(correlationId).matches()) {
            correlationId = UUID.randomUUID().toString();
        }
        MDC.put(RequestContext.MDC_CORRELATION_ID, correlationId);
        MDC.put(RequestContext.MDC_SOURCE_IP, ipResolver.resolve(request));
        response.setHeader(RequestContext.CORRELATION_HEADER, correlationId);
        try {
            chain.doFilter(request, response);
        } finally {
            if (!request.getRequestURI().startsWith("/actuator")) {
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("http_method", request.getMethod());
                details.put("http_path", request.getRequestURI());
                details.put("http_status", response.getStatus());
                details.put("duration_ms", (System.nanoTime() - start) / 1_000_000);
                details.put("user_agent", truncate(request.getHeader("User-Agent")));
                Object user = request.getAttribute(RequestContext.ATTR_USERNAME);
                if (user != null) details.put("username", user.toString());
                events.emit(SecurityEventType.HTTP_REQUEST,
                        response.getStatus() < 400 ? "SUCCESS" : "FAILURE",
                        "%s %s -> %d".formatted(request.getMethod(), request.getRequestURI(), response.getStatus()),
                        details);
            }
            MDC.clear();
        }
    }

    private static String truncate(String value) {
        if (value == null) return null;
        return value.length() > 256 ? value.substring(0, 256) : value;
    }
}
