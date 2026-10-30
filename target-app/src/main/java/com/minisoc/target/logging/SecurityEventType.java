package com.minisoc.target.logging;

/**
 * Catalogue of security-relevant events written to the audit log. The detection
 * service keys its rules off these names, so treat them as a stable contract.
 */
public enum SecurityEventType {
    LOGIN_SUCCESS("authentication"),
    LOGIN_FAILURE("authentication"),
    TOKEN_INVALID("authentication"),
    UNAUTHORIZED("authentication"),
    ACCESS_DENIED("authorization"),
    ADMIN_ACTION("privileged"),
    ORDER_CREATED("business"),
    RESOURCE_OWNERSHIP_VIOLATION("authorization"),
    MALICIOUS_REQUEST("attack"),
    HTTP_REQUEST("access");

    private final String category;

    SecurityEventType(String category) {
        this.category = category;
    }

    public String category() {
        return category;
    }
}
