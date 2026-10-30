package com.minisoc.target.web;

import com.minisoc.target.model.UserProfile;
import com.minisoc.target.service.UserDirectory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserDirectory directory;

    public UserController(UserDirectory directory) {
        this.directory = directory;
    }

    /** ADMIN only (enforced in SecurityConfig). */
    @GetMapping
    public List<UserProfile> list() {
        return directory.findAll();
    }

    @GetMapping("/me")
    public ResponseEntity<UserProfile> me(Authentication auth) {
        return ResponseEntity.of(directory.find(auth.getName()));
    }
}
