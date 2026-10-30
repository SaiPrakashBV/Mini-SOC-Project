package com.minisoc.incidents.repository;

import com.minisoc.incidents.domain.Incident;
import com.minisoc.incidents.domain.IncidentStatus;
import com.minisoc.incidents.domain.Severity;
import com.minisoc.incidents.dto.IncidentFilter;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public final class IncidentSpecifications {

    private IncidentSpecifications() {
    }

    public static Specification<Incident> matching(IncidentFilter f) {
        return (root, query, cb) -> {
            List<Predicate> p = new ArrayList<>();
            if (f.status() != null && !f.status().isEmpty()) {
                p.add(root.<IncidentStatus>get("status").in(f.status()));
            }
            if (f.severity() != null && !f.severity().isEmpty()) {
                p.add(root.<Severity>get("severity").in(f.severity()));
            }
            if (f.assignee() != null) {
                if ("unassigned".equalsIgnoreCase(f.assignee())) {
                    p.add(cb.isNull(root.get("assignee")));
                } else {
                    p.add(cb.equal(root.get("assignee"), f.assignee()));
                }
            }
            if (f.affectedUser() != null) p.add(cb.equal(root.get("affectedUser"), f.affectedUser()));
            if (f.sourceIp() != null) p.add(cb.equal(root.get("sourceIp"), f.sourceIp()));
            if (f.ruleId() != null) p.add(cb.equal(root.get("ruleId"), f.ruleId()));
            if (f.from() != null) p.add(cb.greaterThanOrEqualTo(root.get("createdAt"), f.from()));
            if (f.to() != null) p.add(cb.lessThan(root.get("createdAt"), f.to()));
            if (f.q() != null && !f.q().isBlank()) {
                String like = "%" + f.q().toLowerCase().replace("%", "\\%").replace("_", "\\_") + "%";
                p.add(cb.or(
                        cb.like(cb.lower(root.get("title")), like, '\\'),
                        cb.like(cb.lower(root.get("description")), like, '\\')));
            }
            return cb.and(p.toArray(Predicate[]::new));
        };
    }
}
