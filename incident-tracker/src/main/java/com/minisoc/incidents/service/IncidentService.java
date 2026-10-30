package com.minisoc.incidents.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.minisoc.incidents.domain.HistoryAction;
import com.minisoc.incidents.domain.Incident;
import com.minisoc.incidents.domain.IncidentNote;
import com.minisoc.incidents.domain.IncidentSource;
import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.dto.AssignRequest;
import com.minisoc.incidents.dto.CreateIncidentRequest;
import com.minisoc.incidents.dto.IncidentDetail;
import com.minisoc.incidents.dto.IncidentFilter;
import com.minisoc.incidents.dto.IncidentSummary;
import com.minisoc.incidents.dto.NoteRequest;
import com.minisoc.incidents.dto.PageResponse;
import com.minisoc.incidents.dto.SeverityUpdateRequest;
import com.minisoc.incidents.dto.StatusUpdateRequest;
import com.minisoc.incidents.repository.IncidentRepository;
import com.minisoc.incidents.repository.IncidentSpecifications;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;

@Service
@Transactional
public class IncidentService {

    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final IncidentRepository repository;
    private final ObjectMapper mapper;

    public IncidentService(IncidentRepository repository, ObjectMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    /**
     * Creates an incident. When the request carries a fingerprint that matches an
     * incident still being worked, the detection is folded into that incident
     * instead of opening a duplicate.
     */
    public CreateResult create(CreateIncidentRequest req, String actor, boolean fromDetection) {
        if (req.fingerprint() != null && !req.fingerprint().isBlank()) {
            var existing = repository.findFirstByFingerprintAndStatusInOrderByCreatedAtDesc(
                    req.fingerprint(), IncidentStatus.activeStatuses());
            if (existing.isPresent()) {
                Incident incident = existing.get();
                incident.incrementDetectionCount();
                incident.addHistory(HistoryAction.RETRIGGERED, null,
                        "detection #" + incident.getDetectionCount(), actor);
                if (req.severity().compareTo(incident.getSeverity()) > 0) {
                    incident.addHistory(HistoryAction.SEVERITY_CHANGED, incident.getSeverity().name(),
                            req.severity().name(), actor);
                    incident.setSeverity(req.severity());
                }
                if (req.evidence() != null) incident.setEvidence(writeJson(req.evidence()));
                incident.addNote(new IncidentNote(actor,
                        "Detection re-triggered: " + Objects.requireNonNullElse(req.description(), req.title())));
                log.info("Incident {} re-triggered by fingerprint {}", incident.getId(), req.fingerprint());
                return new CreateResult(toDetail(repository.save(incident)), true);
            }
        }

        Incident incident = new Incident();
        incident.setTitle(req.title());
        incident.setDescription(req.description());
        incident.setSeverity(req.severity());
        incident.setSource(fromDetection ? IncidentSource.DETECTION : IncidentSource.MANUAL);
        incident.setRuleId(req.ruleId());
        incident.setFingerprint(req.fingerprint());
        incident.setAffectedUser(req.affectedUser());
        incident.setSourceIp(req.sourceIp());
        incident.setEvidence(req.evidence() == null ? null : writeJson(req.evidence()));
        incident.setDetectedAt(req.detectedAt());
        incident.setCreatedBy(actor);
        incident.addHistory(HistoryAction.CREATED, null, IncidentStatus.OPEN.name(), actor);
        Incident saved = repository.save(incident);
        log.info("Incident {} created ({} / {}) by {}", saved.getId(), saved.getSeverity(), saved.getRuleId(), actor);
        return new CreateResult(toDetail(saved), false);
    }

    @Transactional(readOnly = true)
    public PageResponse<IncidentSummary> search(IncidentFilter filter, Pageable pageable) {
        return PageResponse.from(repository.findAll(IncidentSpecifications.matching(filter), pageable)
                .map(IncidentSummary::from));
    }

    @Transactional(readOnly = true)
    public IncidentDetail get(long id) {
        return toDetail(load(id));
    }

    public IncidentDetail updateStatus(long id, StatusUpdateRequest req, String actor) {
        Incident incident = load(id);
        IncidentStatus from = incident.getStatus();
        IncidentStatus to = req.status();
        if (from == to) {
            throw new InvalidTransitionException("Incident is already " + to);
        }
        if (!from.canTransitionTo(to)) {
            throw new InvalidTransitionException("Cannot move incident from %s to %s (allowed: %s)"
                    .formatted(from, to, from.allowedTransitions()));
        }
        if (to.requiresResolution() && (req.resolution() == null || req.resolution().isBlank())) {
            throw new InvalidTransitionException("A resolution summary is required to mark an incident " + to);
        }

        incident.setStatus(to);
        incident.addHistory(HistoryAction.STATUS_CHANGED, from.name(), to.name(), actor);
        if (incident.getAcknowledgedAt() == null) incident.setAcknowledgedAt(Instant.now());
        if (to.requiresResolution()) {
            incident.setResolution(req.resolution());
            incident.setResolvedAt(Instant.now());
        } else if (to == IncidentStatus.INVESTIGATING && !from.isActive()) {
            // Re-opened: clear the previous resolution timestamp, keep the text for context.
            incident.setResolvedAt(null);
        }
        if (req.comment() != null && !req.comment().isBlank()) {
            incident.addNote(new IncidentNote(actor, "[%s → %s] %s".formatted(from, to, req.comment())));
        }
        return toDetail(repository.save(incident));
    }

    public IncidentDetail assign(long id, AssignRequest req, String actor) {
        Incident incident = load(id);
        String assignee = req.assignee() == null || req.assignee().isBlank() ? null : req.assignee().trim();
        if (Objects.equals(incident.getAssignee(), assignee)) {
            return toDetail(incident);
        }
        incident.addHistory(HistoryAction.ASSIGNED, incident.getAssignee(), assignee, actor);
        incident.setAssignee(assignee);
        if (assignee != null && incident.getAcknowledgedAt() == null) incident.setAcknowledgedAt(Instant.now());
        return toDetail(repository.save(incident));
    }

    public IncidentDetail updateSeverity(long id, SeverityUpdateRequest req, String actor) {
        Incident incident = load(id);
        if (incident.getSeverity() != req.severity()) {
            incident.addHistory(HistoryAction.SEVERITY_CHANGED, incident.getSeverity().name(),
                    req.severity().name(), actor);
            incident.setSeverity(req.severity());
        }
        return toDetail(repository.save(incident));
    }

    public IncidentDetail.Note addNote(long id, NoteRequest req, String actor) {
        Incident incident = load(id);
        IncidentNote note = new IncidentNote(actor, req.content().trim());
        incident.addNote(note);
        incident.addHistory(HistoryAction.NOTE_ADDED, null, abbreviate(req.content()), actor);
        repository.saveAndFlush(incident);
        return new IncidentDetail.Note(note.getId(), note.getAuthor(), note.getContent(), note.getCreatedAt());
    }

    private Incident load(long id) {
        return repository.findById(id).orElseThrow(() -> new IncidentNotFoundException(id));
    }

    private IncidentDetail toDetail(Incident incident) {
        return IncidentDetail.from(incident, readJson(incident.getEvidence()));
    }

    private String writeJson(JsonNode node) {
        try {
            return mapper.writeValueAsString(node);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Evidence is not valid JSON", e);
        }
    }

    private JsonNode readJson(String json) {
        if (json == null) return null;
        try {
            return mapper.readTree(json);
        } catch (JsonProcessingException e) {
            return mapper.getNodeFactory().textNode(json);
        }
    }

    private static String abbreviate(String s) {
        return s.length() > 120 ? s.substring(0, 117) + "..." : s;
    }
}
