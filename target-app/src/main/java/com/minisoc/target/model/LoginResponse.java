package com.minisoc.target.model;

import java.time.Instant;
import java.util.List;

public record LoginResponse(String accessToken, String tokenType, Instant expiresAt, String username, List<String> roles) {
}
