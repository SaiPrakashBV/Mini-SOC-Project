package com.minisoc.target.model;

import java.math.BigDecimal;
import java.time.Instant;

public record Order(long id, String owner, String item, int quantity, BigDecimal amount, Instant createdAt) {
}
