package com.minisoc.target.security;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

/** Returns 401 for unauthenticated access to protected endpoints and records an UNAUTHORIZED event. */
@Component
public class AuditAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final SecurityEventLogger events;
    private final ErrorResponseWriter writer;

    public AuditAuthenticationEntryPoint(SecurityEventLogger events, ErrorResponseWriter writer) {
        this.events = events;
        this.writer = writer;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
            throws IOException {
        events.failure(SecurityEventType.UNAUTHORIZED, "Unauthenticated access to protected resource",
                Map.of("http_method", request.getMethod(), "http_path", request.getRequestURI(),
                        "reason", ex.getClass().getSimpleName()));
        writer.write(request, response, 401, "Unauthorized", "Authentication required");
    }
}
