package com.minisoc.incidents.web;

import com.minisoc.incidents.config.TrackerSecurityProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Analyst directory for the dashboard (assignment drop-down, "who am I"). */
@RestController
@RequestMapping("/api")
public class AnalystController {

    private final TrackerSecurityProperties props;

    public AnalystController(TrackerSecurityProperties props) {
        this.props = props;
    }

    @GetMapping("/analysts")
    public List<Map<String, String>> analysts() {
        return props.analysts().stream()
                .map(a -> Map.of("username", a.username(), "displayName", a.displayName()))
                .toList();
    }

    @GetMapping("/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of("username", auth.getName(),
                "roles", auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
    }
}
