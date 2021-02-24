package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.security.Principal;

@SpringBootApplication
@RestController
@RequestMapping({"/normal", "/api/normal", "/normal/api"})
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }


    @GetMapping("/")
    @PreAuthorize("hasRole('ROLE_DEV')")
    public Mono<String> getString() {
        return  ReactiveSecurityContextHolder.getContext().map(e -> {
            e.getAuthentication().getAuthorities().forEach(System.out::println);
            System.out.println(e.getAuthentication().getPrincipal().toString());
            return "test" + "\n" + e.getAuthentication().getName();
        });
    }
}
