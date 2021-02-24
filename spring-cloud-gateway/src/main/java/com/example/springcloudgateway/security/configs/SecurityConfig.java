package com.example.springcloudgateway.security.configs;

import com.nimbusds.jwt.JWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final KeyCloakJWTAuthTokenConvertor authTokenConvertor;
    @Value("${spring.application.name}")
    private String appName;

    @Autowired
    public SecurityConfig(KeyCloakJWTAuthTokenConvertor authTokenConvertor) {
        this.authTokenConvertor = authTokenConvertor;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChainToken(ServerHttpSecurity http,
                                                            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        // Security related specifically to api endpoints which uses JWT tokens as authentication passage
        http.authorizeExchange().
                pathMatchers("/" + appName + "/management/**").hasAuthority("ROLE_DEV").
                pathMatchers("**/api/**", "/api/**").
                authenticated().
                and().
                oauth2ResourceServer().
                jwt().
                jwtAuthenticationConverter(authTokenConvertor);

        // If we didn't trigger /api call or didn't pass it through normal means we're going through this security chain
        http.authorizeExchange().
                anyExchange().
                authenticated().
                and().
                oauth2Login();

        http.logout(logout -> logout.logoutSuccessHandler(new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)));

        // Allow showing /home within a frame
        http.headers().frameOptions().mode(Mode.SAMEORIGIN);

        // Disable CSRF in the gateway to prevent conflicts with proxied service CSRF
        http.csrf().disable();
        return http.build();
    }

    @Bean
    GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return new SimpleAuthorityMapper();
    }
}

@Configuration
class KeyCloakJWTAuthTokenConvertor implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
    private final MappedJwtClaimSetConverter delegate = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

    @Override
    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
        final Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
        List<SimpleGrantedAuthority> authorities = ((List<String>) realmAccess.get("roles")).stream()
                .map(roleName -> "ROLE_" + roleName.toUpperCase())
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        String username = (String) this.delegate.convert(jwt.getClaims()).get("preferred_username");
        return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
    }
}
