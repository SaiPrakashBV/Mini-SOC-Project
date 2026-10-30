package com.minisoc.target.model;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

public record CreateOrderRequest(
        @NotBlank @Size(max = 100) String item,
        @Min(1) @Max(1000) int quantity,
        @NotNull @DecimalMin("0.01") BigDecimal amount) {
}
