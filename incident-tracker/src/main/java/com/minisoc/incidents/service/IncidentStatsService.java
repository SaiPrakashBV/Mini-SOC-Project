package com.minisoc.incidents.service;

import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;
import com.minisoc.incidents.dto.IncidentStats;
import com.minisoc.incidents.repository.IncidentRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;

@Service
@Transactional(readOnly = true)
public class IncidentStatsService {

    private static final int TOP_N = 5;

    private final IncidentRepository repository;

    public IncidentStatsService(IncidentRepository repository) {
        this.repository = repository;
    }

    public IncidentStats compute() {
        Map<String, Long> byStatus = zeroed(IncidentStatus.values());
        repository.countByStatus().forEach(r -> byStatus.put(r[0].toString(), (Long) r[1]));

        Map<String, Long> bySeverity = zeroed(Severity.values());
        repository.countBySeverity().forEach(r -> bySeverity.put(r[0].toString(), (Long) r[1]));

        Map<String, Long> activeBySeverity = zeroed(Severity.values());
        repository.countBySeverityForStatuses(IncidentStatus.activeStatuses())
                .forEach(r -> activeBySeverity.put(r[0].toString(), (Long) r[1]));

        long total = byStatus.values().stream().mapToLong(Long::longValue).sum();
        long active = activeBySeverity.values().stream().mapToLong(Long::longValue).sum();
        Instant dayAgo = Instant.now().minus(Duration.ofHours(24));

        return new IncidentStats(
                total,
                active,
                repository.countByAssigneeIsNullAndStatusIn(IncidentStatus.activeStatuses()),
                repository.countByCreatedAtAfter(dayAgo),
                repository.countByResolvedAtAfter(dayAgo),
                meanMinutes(repository.acknowledgementTimes()),
                meanMinutes(repository.resolutionTimes()),
                byStatus,
                bySeverity,
                activeBySeverity,
                counts(repository.topAffectedUsers(PageRequest.of(0, TOP_N))),
                counts(repository.topSourceIps(PageRequest.of(0, TOP_N))),
                counts(repository.topRules(PageRequest.of(0, TOP_N))));
    }

    private static Map<String, Long> zeroed(Enum<?>[] values) {
        Map<String, Long> map = new LinkedHashMap<>();
        for (Enum<?> v : values) map.put(v.name(), 0L);
        return map;
    }

    private static Double meanMinutes(List<Object[]> pairs) {
        OptionalDouble avg = pairs.stream()
                .mapToLong(r -> Duration.between((Instant) r[0], (Instant) r[1]).toSeconds())
                .average();
        return avg.isPresent() ? Math.round(avg.getAsDouble() / 60.0 * 10) / 10.0 : null;
    }

    private static List<IncidentStats.Count> counts(List<Object[]> rows) {
        return rows.stream().map(r -> new IncidentStats.Count(r[0].toString(), (Long) r[1])).toList();
    }
}
