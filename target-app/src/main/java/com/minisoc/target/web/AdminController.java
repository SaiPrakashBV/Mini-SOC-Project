package com.minisoc.target.web;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import com.minisoc.target.service.OrderService;
import com.minisoc.target.service.UserDirectory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.time.Instant;
import java.util.Map;

/** Privileged endpoints. Access is restricted to ROLE_ADMIN in SecurityConfig. */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserDirectory users;
    private final OrderService orders;
    private final SecurityEventLogger events;

    public AdminController(UserDirectory users, OrderService orders, SecurityEventLogger events) {
        this.users = users;
        this.orders = orders;
        this.events = events;
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        events.success(SecurityEventType.ADMIN_ACTION, "Admin viewed system stats", Map.of("action", "view_stats"));
        return Map.of(
                "users", users.findAll().size(),
                "orders", orders.findAll().size(),
                "uptimeSeconds", ManagementFactory.getRuntimeMXBean().getUptime() / 1000,
                "timestamp", Instant.now().toString());
    }

    @PostMapping("/maintenance")
    public Map<String, Object> maintenance() {
        events.success(SecurityEventType.ADMIN_ACTION, "Admin triggered maintenance task",
                Map.of("action", "maintenance"));
        return Map.of("status", "scheduled", "timestamp", Instant.now().toString());
    }
}
