package com.minisoc.target.security;

import com.minisoc.target.logging.RequestContext;
import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Authenticates requests carrying {@code Authorization: Bearer <jwt>}. Invalid tokens are
 * logged as TOKEN_INVALID and the request continues unauthenticated, so the entry point
 * produces the 401.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";

    private final JwtService jwtService;
    private final SecurityEventLogger events;

    public JwtAuthenticationFilter(JwtService jwtService, SecurityEventLogger events) {
        this.jwtService = jwtService;
        this.events = events;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER)) {
            try {
                Claims claims = jwtService.parse(header.substring(BEARER.length()));
                String username = claims.getSubject();
                @SuppressWarnings("unchecked")
                List<String> roles = claims.get("roles", List.class);
                var authorities = roles == null ? List.<SimpleGrantedAuthority>of()
                        : roles.stream().map(SimpleGrantedAuthority::new).toList();
                var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
                MDC.put(RequestContext.MDC_USERNAME, username);
                request.setAttribute(RequestContext.ATTR_USERNAME, username);
            } catch (ExpiredJwtException e) {
                events.failure(SecurityEventType.TOKEN_INVALID, "Expired JWT presented",
                        Map.of("reason", "expired", "username", String.valueOf(e.getClaims().getSubject()),
                                "http_path", request.getRequestURI()));
            } catch (JwtException | IllegalArgumentException e) {
                events.failure(SecurityEventType.TOKEN_INVALID, "Invalid JWT presented",
                        Map.of("reason", e.getClass().getSimpleName(), "http_path", request.getRequestURI()));
            }
        }
        chain.doFilter(request, response);
    }
}
