package com.example.democlient2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.netty.http.server.HttpServerRequest;

@SpringBootApplication
@RestController
@RequestMapping({"/something", "/something/api"})
public class DemoClient2Application {

    public static void main(String[] args) {
        SpringApplication.run(DemoClient2Application.class, args);
    }


    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_DEV')")
    @GetMapping("/")
    public String getValue() {
        return "something";
    }
}
