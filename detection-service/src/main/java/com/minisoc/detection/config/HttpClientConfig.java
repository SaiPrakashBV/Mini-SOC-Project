package com.minisoc.detection.config;

import com.minisoc.detection.opensearch.OpenSearchClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

@Configuration
public class HttpClientConfig {

    private static JdkClientHttpRequestFactory requestFactory() {
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(Duration.ofSeconds(15));
        return factory;
    }

    @Bean
    OpenSearchClient openSearchClient(RestClient.Builder builder, DetectionProperties props) {
        var os = props.opensearch();
        var b = builder.clone().baseUrl(os.url()).requestFactory(requestFactory());
        if (os.username() != null && !os.username().isBlank()) {
            String creds = Base64.getEncoder()
                    .encodeToString((os.username() + ":" + os.password()).getBytes(StandardCharsets.UTF_8));
            b.defaultHeader(HttpHeaders.AUTHORIZATION, "Basic " + creds);
        }
        return new OpenSearchClient(b.build());
    }

    @Bean
    RestClient trackerClient(RestClient.Builder builder, DetectionProperties props) {
        return builder.clone()
                .baseUrl(props.tracker().url())
                .requestFactory(requestFactory())
                .defaultHeader("X-API-Key", props.tracker().apiKey())
                .build();
    }
}
