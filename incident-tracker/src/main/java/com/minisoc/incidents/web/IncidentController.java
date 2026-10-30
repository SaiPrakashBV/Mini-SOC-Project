package com.minisoc.incidents.web;

import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;
import com.minisoc.incidents.dto.AssignRequest;
import com.minisoc.incidents.dto.CreateIncidentRequest;
import com.minisoc.incidents.dto.IncidentDetail;
import com.minisoc.incidents.dto.IncidentFilter;
import com.minisoc.incidents.dto.IncidentStats;
import com.minisoc.incidents.dto.IncidentSummary;
import com.minisoc.incidents.dto.NoteRequest;
import com.minisoc.incidents.dto.PageResponse;
import com.minisoc.incidents.dto.SeverityUpdateRequest;
import com.minisoc.incidents.dto.StatusUpdateRequest;
import com.minisoc.incidents.service.IncidentService;
import com.minisoc.incidents.service.IncidentStatsService;
import jakarta.validation.Valid;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private static final Set<String> SORTABLE = Set.of("createdAt", "updatedAt", "severity", "status", "detectedAt", "id");

    private final IncidentService incidents;
    private final IncidentStatsService stats;

    public IncidentController(IncidentService incidents, IncidentStatsService stats) {
        this.incidents = incidents;
        this.stats = stats;
    }

    @PostMapping
    public ResponseEntity<IncidentDetail> create(@Valid @RequestBody CreateIncidentRequest request, Authentication auth) {
        boolean fromService = auth.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_SERVICE"));
        var result = incidents.create(request, auth.getName(), fromService);
        if (result.deduplicated()) {
            return ResponseEntity.ok().header("X-Incident-Deduplicated", "true").body(result.incident());
        }
        var location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
                .buildAndExpand(result.incident().id()).toUri();
        return ResponseEntity.created(location).body(result.incident());
    }

    @GetMapping
    public PageResponse<IncidentSummary> list(
            @RequestParam(required = false) List<IncidentStatus> status,
            @RequestParam(required = false) List<Severity> severity,
            @RequestParam(required = false) String assignee,
            @RequestParam(required = false) String affectedUser,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String ruleId,
            @RequestParam(required = false) String q,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sort,
            @RequestParam(defaultValue = "desc") String direction) {
        if (!SORTABLE.contains(sort)) sort = "createdAt";
        var pageable = PageRequest.of(Math.max(page, 0), Math.clamp(size, 1, 200),
                Sort.by(Sort.Direction.fromOptionalString(direction).orElse(Sort.Direction.DESC), sort));
        var filter = new IncidentFilter(status, severity, assignee, affectedUser, sourceIp, ruleId, q, from, to);
        return incidents.search(filter, pageable);
    }

    @GetMapping("/stats")
    public IncidentStats stats() {
        return stats.compute();
    }

    @GetMapping("/{id}")
    public IncidentDetail get(@PathVariable long id) {
        return incidents.get(id);
    }

    @PatchMapping("/{id}/status")
    public IncidentDetail updateStatus(@PathVariable long id, @Valid @RequestBody StatusUpdateRequest request,
                                       Authentication auth) {
        return incidents.updateStatus(id, request, auth.getName());
    }

    @PatchMapping("/{id}/assign")
    public IncidentDetail assign(@PathVariable long id, @Valid @RequestBody AssignRequest request, Authentication auth) {
        return incidents.assign(id, request, auth.getName());
    }

    @PatchMapping("/{id}/severity")
    public IncidentDetail updateSeverity(@PathVariable long id, @Valid @RequestBody SeverityUpdateRequest request,
                                         Authentication auth) {
        return incidents.updateSeverity(id, request, auth.getName());
    }

    @PostMapping("/{id}/notes")
    public ResponseEntity<IncidentDetail.Note> addNote(@PathVariable long id, @Valid @RequestBody NoteRequest request,
                                                       Authentication auth) {
        return ResponseEntity.status(HttpStatus.CREATED).body(incidents.addNote(id, request, auth.getName()));
    }
}
