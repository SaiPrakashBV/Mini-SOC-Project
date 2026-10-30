package com.minisoc.incidents.service;

public class IncidentNotFoundException extends RuntimeException {
    public IncidentNotFoundException(long id) {
        super("Incident " + id + " not found");
    }
}
