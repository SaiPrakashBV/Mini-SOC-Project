package com.minisoc.target.logging;

import com.minisoc.target.config.AppSecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Resolves the caller's IP. X-Forwarded-For is only honoured when explicitly enabled
 * (behind a trusted proxy, or for attack simulation) because clients can forge it.
 */
@Component
public class ClientIpResolver {

    private final boolean trustForwardedFor;

    public ClientIpResolver(AppSecurityProperties props) {
        this.trustForwardedFor = props.trustForwardedFor();
    }

    public String resolve(HttpServletRequest request) {
        if (trustForwardedFor) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }
}
