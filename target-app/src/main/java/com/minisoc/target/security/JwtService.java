package com.minisoc.target.security;

import com.minisoc.target.config.AppSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final AppSecurityProperties props;

    public JwtService(AppSecurityProperties props) {
        this.props = props;
        this.key = Keys.hmacShaKeyFor(props.jwtSecret().getBytes(StandardCharsets.UTF_8));
    }

    public IssuedToken issue(UserDetails user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(props.jwtTtl());
        List<String> roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        String token = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(props.jwtIssuer())
                .subject(user.getUsername())
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key)
                .compact();
        return new IssuedToken(token, expiry);
    }

    /** Parses and verifies the token; throws {@link JwtException} when invalid or expired. */
    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(props.jwtIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public record IssuedToken(String token, Instant expiresAt) {
    }
}
