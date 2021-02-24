package com.example.democlient2.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@EnableWebFluxSecurity
@Configuration
public class SecurityConfig {
    private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity) {
        httpSecurity.authorizeExchange().
                anyExchange().
                authenticated().
                and().
                oauth2ResourceServer().
                jwt().
                jwtAuthenticationConverter(jwt -> {
                    final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
                    List<SimpleGrantedAuthority> authorities = ((List<String>) realmAccess.get("roles")).stream()
                            .map(roleName -> "ROLE_" + roleName.toUpperCase())
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    String username = (String) this.delegate.convert(jwt.getClaims()).get("preferred_username");
                    return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
                });

        return httpSecurity.build();
    }
}
