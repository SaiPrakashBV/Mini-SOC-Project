package com.minisoc.target.service;

import com.minisoc.target.model.CreateOrderRequest;
import com.minisoc.target.model.Order;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** In-memory order store; enough to generate realistic business and authorization events. */
@Service
public class OrderService {

    private final Map<Long, Order> orders = new ConcurrentHashMap<>();
    private final AtomicLong sequence = new AtomicLong(1000);

    public OrderService() {
        seed("alice", "Laptop", 1, "1299.00");
        seed("alice", "USB-C Dock", 2, "179.98");
        seed("bob", "Monitor", 1, "349.50");
        seed("bob", "Keyboard", 1, "89.99");
    }

    private void seed(String owner, String item, int qty, String amount) {
        long id = sequence.incrementAndGet();
        orders.put(id, new Order(id, owner, item, qty, new BigDecimal(amount), Instant.now()));
    }

    public List<Order> findAll() {
        return orders.values().stream().sorted(Comparator.comparingLong(Order::id)).toList();
    }

    public List<Order> findByOwner(String owner) {
        return findAll().stream().filter(o -> o.owner().equals(owner)).toList();
    }

    public Optional<Order> findById(long id) {
        return Optional.ofNullable(orders.get(id));
    }

    public Order create(String owner, CreateOrderRequest request) {
        long id = sequence.incrementAndGet();
        Order order = new Order(id, owner, request.item(), request.quantity(), request.amount(), Instant.now());
        orders.put(id, order);
        return order;
    }
}
