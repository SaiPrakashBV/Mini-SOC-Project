package com.minisoc.target.service;

import com.minisoc.target.config.AppSecurityProperties;
import com.minisoc.target.model.UserProfile;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/** Read-only directory of the demo users configured in app.security.users. */
@Service
public class UserDirectory {

    private final List<UserProfile> profiles;

    public UserDirectory(AppSecurityProperties props) {
        this.profiles = props.users().stream()
                .map(u -> new UserProfile(u.username(), u.email(), List.copyOf(u.roles())))
                .toList();
    }

    public List<UserProfile> findAll() {
        return profiles;
    }

    public Optional<UserProfile> find(String username) {
        return profiles.stream().filter(p -> p.username().equals(username)).findFirst();
    }
}
