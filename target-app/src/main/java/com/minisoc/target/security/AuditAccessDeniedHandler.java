package com.minisoc.target.security;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/** Returns 403 when an authenticated user lacks the required role and records ACCESS_DENIED. */
@Component
public class AuditAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityEventLogger events;
    private final ErrorResponseWriter writer;

    public AuditAccessDeniedHandler(SecurityEventLogger events, ErrorResponseWriter writer) {
        this.events = events;
        this.writer = writer;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
            throws IOException {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("http_method", request.getMethod());
        details.put("http_path", request.getRequestURI());
        details.put("restricted_resource", request.getRequestURI().startsWith("/api/admin"));
        if (auth != null) {
            details.put("username", auth.getName());
            details.put("roles", auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).collect(Collectors.joining(",")));
        }
        events.failure(SecurityEventType.ACCESS_DENIED, "Access denied to restricted resource", details);
        writer.write(request, response, 403, "Forbidden", "You do not have permission to access this resource");
    }
}
