package com.minisoc.target.web;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import com.minisoc.target.model.LoginRequest;
import com.minisoc.target.model.LoginResponse;
import com.minisoc.target.security.JwtService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecurityEventLogger events;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService,
                          SecurityEventLogger events) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.events = events;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        String username = request.username().trim();
        try {
            var auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, request.password()));
            UserDetails user = (UserDetails) auth.getPrincipal();
            var token = jwtService.issue(user);
            var roles = user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
            events.success(SecurityEventType.LOGIN_SUCCESS, "User authenticated",
                    Map.of("username", username, "roles", String.join(",", roles)));
            return ResponseEntity.ok(new LoginResponse(token.token(), "Bearer", token.expiresAt(), username, roles));
        } catch (AuthenticationException e) {
            events.failure(SecurityEventType.LOGIN_FAILURE, "Authentication failed",
                    Map.of("username", username, "reason", e.getClass().getSimpleName()));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized", "message", "Invalid username or password"));
        }
    }
}
