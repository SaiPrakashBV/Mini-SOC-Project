package com.minisoc.detection;

import com.minisoc.detection.config.DetectionProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Boots the full context with the real application.yml rules to catch config/binding errors. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class ApplicationContextTest {

    @Autowired
    DetectionProperties props;

    @Autowired
    MockMvc mvc;

    @Test
    void rulesBindFromYaml() {
        assertThat(props.rules()).extracting("id").contains("BRUTE_FORCE_LOGIN", "AUTH_ERROR_SPIKE",
                "HIGH_REQUEST_RATE", "RESTRICTED_ENDPOINT_ACCESS");
        var bruteForce = props.rules().stream().filter(r -> r.id().equals("BRUTE_FORCE_LOGIN")).findFirst().orElseThrow();
        assertThat(bruteForce.match()).containsKey("event_type");
        var authSpike = props.rules().stream().filter(r -> r.id().equals("AUTH_ERROR_SPIKE")).findFirst().orElseThrow();
        assertThat(authSpike.match().get("http_status")).containsExactly("401", "403");
    }

    @Test
    void apiRequiresAnalystLogin() throws Exception {
        mvc.perform(get("/api/rules")).andExpect(status().isUnauthorized());
    }
}
