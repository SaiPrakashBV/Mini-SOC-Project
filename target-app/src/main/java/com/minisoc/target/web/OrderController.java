package com.minisoc.target.web;

import com.minisoc.target.logging.SecurityEventLogger;
import com.minisoc.target.logging.SecurityEventType;
import com.minisoc.target.model.CreateOrderRequest;
import com.minisoc.target.model.Order;
import com.minisoc.target.service.OrderService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService orders;
    private final SecurityEventLogger events;

    public OrderController(OrderService orders, SecurityEventLogger events) {
        this.orders = orders;
        this.events = events;
    }

    @GetMapping
    public List<Order> list(Authentication auth) {
        return isAdmin(auth) ? orders.findAll() : orders.findByOwner(auth.getName());
    }

    @GetMapping("/{id}")
    public Order get(@PathVariable long id, Authentication auth) {
        Order order = orders.findById(id)
                .orElseThrow(() -> new NotFoundException("Order " + id + " not found"));
        if (!order.owner().equals(auth.getName()) && !isAdmin(auth)) {
            // Possible IDOR / horizontal privilege escalation attempt.
            events.failure(SecurityEventType.RESOURCE_OWNERSHIP_VIOLATION, "Attempt to read another user's order",
                    Map.of("resource", "order", "resource_id", id, "resource_owner", order.owner()));
            throw new AccessDeniedException("Not your order");
        }
        return order;
    }

    @PostMapping
    public ResponseEntity<Order> create(@Valid @RequestBody CreateOrderRequest request, Authentication auth) {
        Order order = orders.create(auth.getName(), request);
        events.success(SecurityEventType.ORDER_CREATED, "Order created",
                Map.of("resource_id", order.id(), "amount", order.amount()));
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }

    private static boolean isAdmin(Authentication auth) {
        return auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }
}
