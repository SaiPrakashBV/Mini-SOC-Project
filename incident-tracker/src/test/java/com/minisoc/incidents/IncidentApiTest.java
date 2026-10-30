package com.minisoc.incidents;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentApiTest {

    private static final String API_KEY = "test-api-key-0123456789";

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper mapper;

    private long createDetection(String fingerprint) throws Exception {
        String body = """
                {"title":"Potential brute-force against alice","severity":"HIGH","ruleId":"BRUTE_FORCE_LOGIN",
                 "fingerprint":"%s","affectedUser":"alice","sourceIp":"10.0.0.5",
                 "evidence":{"count":5,"window":"2m"}}
                """.formatted(fingerprint);
        String response = mvc.perform(post("/api/incidents").header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn().getResponse().getContentAsString();
        return mapper.readTree(response).get("id").asLong();
    }

    @Test
    void unauthenticatedRequestsAreRejected() throws Exception {
        mvc.perform(get("/api/incidents")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/incidents").header("X-API-Key", "wrong")).andExpect(status().isUnauthorized());
    }

    @Test
    void detectionCreatesIncidentAndDeduplicatesByFingerprint() throws Exception {
        long id = createDetection("BRUTE_FORCE_LOGIN:alice:dedup-test");
        mvc.perform(post("/api/incidents").header("X-API-Key", API_KEY).contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title":"again","severity":"CRITICAL","fingerprint":"BRUTE_FORCE_LOGIN:alice:dedup-test"}
                                """))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Incident-Deduplicated", "true"))
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.detectionCount").value(2))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.source").value("DETECTION"));
    }

    @Test
    void serviceCannotChangeIncidentState() throws Exception {
        long id = createDetection("svc-cannot-patch");
        mvc.perform(patch("/api/incidents/{id}/status", id).header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INVESTIGATING\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void analystWorkflow() throws Exception {
        long id = createDetection("workflow-test");
        var analyst = httpBasic("analyst1", "analyst-pass");

        mvc.perform(patch("/api/incidents/{id}/assign", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"assignee\":\"analyst1\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.assignee").value("analyst1"));

        mvc.perform(patch("/api/incidents/{id}/status", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"INVESTIGATING\"}"))
                .andExpect(status().isOk());

        mvc.perform(post("/api/incidents/{id}/notes", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"Source IP belongs to a known scanner\"}"))
                .andExpect(status().isCreated());

        // RESOLVED without a resolution summary is refused.
        mvc.perform(patch("/api/incidents/{id}/status", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"RESOLVED\"}"))
                .andExpect(status().isConflict());

        mvc.perform(patch("/api/incidents/{id}/status", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"RESOLVED\",\"resolution\":\"IP blocked, password reset\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESOLVED"))
                .andExpect(jsonPath("$.resolvedAt").exists());

        // Illegal jump back to OPEN.
        mvc.perform(patch("/api/incidents/{id}/status", id).with(analyst)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"OPEN\"}"))
                .andExpect(status().isConflict());

        mvc.perform(get("/api/incidents/{id}", id).with(analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.notes.length()").value(1))
                .andExpect(jsonPath("$.history.length()").value(5));
    }

    @Test
    void listFiltersAndStats() throws Exception {
        createDetection("filter-test");
        var analyst = httpBasic("analyst1", "analyst-pass");
        mvc.perform(get("/api/incidents").param("severity", "HIGH").param("status", "OPEN").with(analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
        mvc.perform(get("/api/incidents/stats").with(analyst))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").isNumber())
                .andExpect(jsonPath("$.bySeverity.HIGH").isNumber());
    }
}
