package com.minisoc.incidents.repository;

import com.minisoc.incidents.domain.Incident;
import com.minisoc.incidents.domain.IncidentStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface IncidentRepository extends JpaRepository<Incident, Long>, JpaSpecificationExecutor<Incident> {

    Optional<Incident> findFirstByFingerprintAndStatusInOrderByCreatedAtDesc(String fingerprint,
                                                                            Collection<IncidentStatus> statuses);

    @Query("select i.status, count(i) from Incident i group by i.status")
    List<Object[]> countByStatus();

    @Query("select i.severity, count(i) from Incident i group by i.severity")
    List<Object[]> countBySeverity();

    @Query("select i.severity, count(i) from Incident i where i.status in :statuses group by i.severity")
    List<Object[]> countBySeverityForStatuses(@Param("statuses") Collection<IncidentStatus> statuses);

    long countByAssigneeIsNullAndStatusIn(Collection<IncidentStatus> statuses);

    long countByCreatedAtAfter(Instant since);

    long countByResolvedAtAfter(Instant since);

    @Query("select i.createdAt, i.acknowledgedAt from Incident i where i.acknowledgedAt is not null")
    List<Object[]> acknowledgementTimes();

    @Query("select i.createdAt, i.resolvedAt from Incident i where i.resolvedAt is not null")
    List<Object[]> resolutionTimes();

    @Query("select i.affectedUser, count(i) from Incident i where i.affectedUser is not null "
            + "group by i.affectedUser order by count(i) desc")
    List<Object[]> topAffectedUsers(Pageable pageable);

    @Query("select i.sourceIp, count(i) from Incident i where i.sourceIp is not null "
            + "group by i.sourceIp order by count(i) desc")
    List<Object[]> topSourceIps(Pageable pageable);

    @Query("select i.ruleId, count(i) from Incident i where i.ruleId is not null "
            + "group by i.ruleId order by count(i) desc")
    List<Object[]> topRules(Pageable pageable);
}
