package com.minisoc.incidents.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, TrackerSecurityProperties props) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable) // stateless API, no cookies
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Basic without WWW-Authenticate realm prompt would be nicer for SPAs, but the
                // dashboard always sends credentials so the browser dialog never appears.
                .httpBasic(b -> b.realmName("mini-soc"))
                .addFilterBefore(new ApiKeyAuthenticationFilter(props.serviceApiKey()),
                        BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/incidents").hasAnyRole("SERVICE", "ANALYST")
                        .requestMatchers(HttpMethod.GET, "/api/**").hasAnyRole("SERVICE", "ANALYST")
                        .requestMatchers("/api/**").hasRole("ANALYST")
                        .anyRequest().denyAll())
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService analystDirectory(TrackerSecurityProperties props, PasswordEncoder encoder) {
        var manager = new InMemoryUserDetailsManager();
        props.analysts().forEach(a -> manager.createUser(User.withUsername(a.username())
                .password(encoder.encode(a.password()))
                .roles(a.roles().toArray(String[]::new))
                .build()));
        return manager;
    }
}
