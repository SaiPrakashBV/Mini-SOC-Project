package com.minisoc.target.model;

import java.util.List;

public record UserProfile(String username, String email, List<String> roles) {
}
