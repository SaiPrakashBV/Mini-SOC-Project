package com.minisoc.target;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class TargetApplication {

    public static void main(String[] args) {
        SpringApplication.run(TargetApplication.class, args);
    }
}
