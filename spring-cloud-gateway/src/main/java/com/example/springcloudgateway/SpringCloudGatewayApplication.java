package com.example.springcloudgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@SpringBootApplication
@RestController
public class SpringCloudGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringCloudGatewayApplication.class, args);
    }

    @GetMapping("/roles")
    public Mono<String> getRoles() {
        return ReactiveSecurityContextHolder.getContext().map(e -> e.getAuthentication().getAuthorities().stream().
                map(GrantedAuthority::getAuthority).
                reduce(e.getAuthentication().getName(), (a, b) -> a + "\n" + b));
    }
}
