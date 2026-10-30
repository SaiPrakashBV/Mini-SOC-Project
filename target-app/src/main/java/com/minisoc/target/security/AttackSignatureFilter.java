package com.minisoc.target.security;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Minimal WAF-style input inspection. Looks for well-known attack payloads in the
 * request path, query parameters and headers, records a MALICIOUS_REQUEST event and
 * blocks the request with 400. Scanner user agents are logged but not blocked.
 *
 * Signatures are intentionally simple - this is a teaching aid, not a substitute for
 * parameterised queries, output encoding and a real WAF. Request bodies are not
 * inspected (that would consume the input stream before the controller reads it).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1) // after RequestLoggingFilter so correlation id / IP are set
public class AttackSignatureFilter extends OncePerRequestFilter {

    private static final int MAX_INSPECTED_LENGTH = 4096;
    private static final Set<String> SKIPPED_HEADERS = Set.of("authorization", "cookie", "content-length");

    /**
     * Checked in order; the first match wins. JNDI goes first because it also contains "${",
     * and command injection before path traversal so "; cat /etc/passwd" is labelled correctly.
     */
    private static final List<Signature> PAYLOAD_SIGNATURES = List.of(
            new Signature("jndi_injection", Pattern.compile(
                    "\\$\\{[^}]*(jndi|lower:j|upper:j|::-j)", Pattern.CASE_INSENSITIVE)),
            new Signature("sql_injection", Pattern.compile(
                    "(\\bunion\\b\\s+(all\\s+)?\\bselect\\b|\\bselect\\b.+\\bfrom\\b|\\binsert\\s+into\\b"
                            + "|\\bdrop\\s+table\\b|'\\s*(or|and)\\s+'?\\w*'?\\s*=\\s*'?\\w*|\\bor\\s+1\\s*=\\s*1\\b"
                            + "|'\\s*;\\s*--|\\b(pg_)?sleep\\s*\\(\\s*\\d+\\s*\\)|;\\s*(select|drop|delete|update|insert|shutdown)\\b|\\bbenchmark\\s*\\(|\\bwaitfor\\s+delay\\b)",
                    Pattern.CASE_INSENSITIVE)),
            new Signature("xss", Pattern.compile(
                    "(<\\s*script|javascript:|\\bon(error|load|mouseover)\\s*=|<\\s*(img|svg|iframe)\\b)",
                    Pattern.CASE_INSENSITIVE)),
            new Signature("command_injection", Pattern.compile(
                    "([;|&]\\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|powershell)\\b|\\$\\([^)]*\\)|`[^`]+`)",
                    Pattern.CASE_INSENSITIVE)),
            new Signature("path_traversal", Pattern.compile(
                    "(\\.\\./|\\.\\.\\\\|/etc/(passwd|shadow)|c:\\\\windows)", Pattern.CASE_INSENSITIVE)));

    private static final Pattern SCANNER_USER_AGENT = Pattern.compile(
            "(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|feroxbuster|wpscan|nuclei|acunetix|nessus|openvas|hydra)",
            Pattern.CASE_INSENSITIVE);

    private final SecurityEventLogger events;
    private final ErrorResponseWriter writer;

    public AttackSignatureFilter(SecurityEventLogger events, ErrorResponseWriter writer) {
        this.events = events;
        this.writer = writer;
    }

    record Signature(String attackType, Pattern pattern) {
    }

    record Finding(String attackType, String location, String sample) {
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Optional<Finding> finding = inspect(request);
        if (finding.isPresent()) {
            Finding f = finding.get();
            events.failure(SecurityEventType.MALICIOUS_REQUEST, "Blocked request containing " + f.attackType(),
                    details(request, f));
            writer.write(request, response, 400, "Bad Request", "Request blocked by input validation");
            return;
        }
        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null && SCANNER_USER_AGENT.matcher(userAgent).find()) {
            events.failure(SecurityEventType.MALICIOUS_REQUEST, "Known security scanner user agent",
                    details(request, new Finding("scanner_tool", "header:user-agent", userAgent)));
        }
        chain.doFilter(request, response);
    }

    static Optional<Finding> inspect(HttpServletRequest request) {
        Map<String, String> inputs = new LinkedHashMap<>();
        inputs.put("path", request.getRequestURI());
        request.getParameterMap().forEach((name, values) -> {
            for (String v : values) inputs.merge("param:" + name, v, (a, b) -> a + " " + b);
        });
        for (String name : Collections.list(request.getHeaderNames())) {
            if (SKIPPED_HEADERS.contains(name.toLowerCase())) continue;
            inputs.put("header:" + name.toLowerCase(), String.join(" ", Collections.list(request.getHeaders(name))));
        }
        for (Signature sig : PAYLOAD_SIGNATURES) {
            for (Map.Entry<String, String> input : inputs.entrySet()) {
                String value = truncate(input.getValue(), MAX_INSPECTED_LENGTH);
                if (value != null && sig.pattern().matcher(value).find()) {
                    return Optional.of(new Finding(sig.attackType(), input.getKey(), value));
                }
            }
        }
        return Optional.empty();
    }

    private static Map<String, Object> details(HttpServletRequest request, Finding f) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("attack_type", f.attackType());
        d.put("attack_location", f.location());
        d.put("attack_sample", truncate(f.sample(), 256));
        d.put("http_method", request.getMethod());
        d.put("http_path", request.getRequestURI());
        return d;
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() > max ? s.substring(0, max) : s;
    }
}
