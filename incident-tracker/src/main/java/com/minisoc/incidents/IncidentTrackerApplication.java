package com.minisoc.incidents;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class IncidentTrackerApplication {

    public static void main(String[] args) {
        SpringApplication.run(IncidentTrackerApplication.class, args);
    }
}
