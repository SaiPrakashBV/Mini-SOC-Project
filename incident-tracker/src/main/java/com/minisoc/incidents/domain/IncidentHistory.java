package com.minisoc.incidents.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.time.Instant;

/** Append-only audit trail of every change made to an incident. */
@Entity
@Table(name = "incident_history")
public class IncidentHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private HistoryAction action;

    @Column(name = "from_value", length = 500)
    private String fromValue;

    @Column(name = "to_value", length = 500)
    private String toValue;

    @Column(nullable = false, length = 100)
    private String actor;

    @Column(nullable = false, updatable = false)
    private Instant timestamp;

    protected IncidentHistory() {
    }

    IncidentHistory(Incident incident, HistoryAction action, String fromValue, String toValue, String actor) {
        this.incident = incident;
        this.action = action;
        this.fromValue = truncate(fromValue);
        this.toValue = truncate(toValue);
        this.actor = actor;
        this.timestamp = Instant.now();
    }

    private static String truncate(String v) {
        return v != null && v.length() > 500 ? v.substring(0, 497) + "..." : v;
    }

    public Long getId() { return id; }
    public HistoryAction getAction() { return action; }
    public String getFromValue() { return fromValue; }
    public String getToValue() { return toValue; }
    public String getActor() { return actor; }
    public Instant getTimestamp() { return timestamp; }
}
