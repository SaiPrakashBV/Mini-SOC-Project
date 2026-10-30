package com.minisoc.detection.opensearch;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/** Thin wrapper over the OpenSearch REST API - just the calls this service needs. */
public class OpenSearchClient {

    private final RestClient http;

    public OpenSearchClient(RestClient http) {
        this.http = http;
    }

    /** Runs a search; missing indices are ignored so rules work before the first event arrives. */
    public JsonNode search(String indexPattern, Object body) {
        return http.post()
                .uri("/{index}/_search?ignore_unavailable=true&allow_no_indices=true", indexPattern)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(JsonNode.class);
    }

    public void index(String index, String id, Object document) {
        http.put()
                .uri("/{index}/_doc/{id}?refresh=wait_for", index, id)
                .contentType(MediaType.APPLICATION_JSON)
                .body(document)
                .retrieve()
                .toBodilessEntity();
    }

    public void update(String index, String id, Object partialDoc) {
        http.post()
                .uri("/{index}/_update/{id}", index, id)
                .contentType(MediaType.APPLICATION_JSON)
                .body(java.util.Map.of("doc", partialDoc))
                .retrieve()
                .toBodilessEntity();
    }

    public boolean ping() {
        try {
            return http.get().uri("/_cluster/health").retrieve()
                    .onStatus(HttpStatusCode::isError, (req, res) -> { })
                    .toBodilessEntity().getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            return false;
        }
    }
}
