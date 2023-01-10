package com.rl.client.config;

import com.rl.client.config.SecurityUtils.SecurityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;


@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfig {

    private static final String[] PERMIT_ALL_LIST_URLS = {
            "/index",
            "/register/*",
            "/verifyRegistration*",
            "/resendVerifyToken*"
    };

    private static final String[] IGNORING_SECURITY_URL = {
            "/resources/**",
            "/statics/**",
            "/css/**",
            "/js/**",
            "/images/**",
            "/incl/**",
            "/webjars/**"
    };

    private static final String[] ADMIN_LIST_URLS = {
            "/admin/*"
    };

    private static final String[] USER_LIST_URLS = {
            "/user/*"
    };

    private static final String[] TEST_LIST_URLS = {
            "/test/*"
    };

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf()
                .disable()
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                        .requestMatchers(PERMIT_ALL_LIST_URLS).permitAll()
                        .requestMatchers(ADMIN_LIST_URLS).hasAuthority("ROLE_ADMIN")
                        .requestMatchers(USER_LIST_URLS).hasAuthority("ROLE_USER")
                        .requestMatchers(TEST_LIST_URLS).hasAuthority("ROLE_TEST")
                        .requestMatchers("/api/**").authenticated()
                )
                .oauth2Login(oauth2login ->
                        oauth2login.loginPage("/oauth2/authorization/api-client-oidc"))
                .oauth2Client(Customizer.withDefaults())
                .logout()
                    .logoutSuccessUrl("http://localhost:9000/logout_user")
                    .deleteCookies("JSESSIONID");

        return http.build();
    }

    @Bean
    public static GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcUserAuthority) {

                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    mappedAuthorities.addAll(SecurityUtils.extractAuthorityFromClaims(idToken.getClaims()));

                } else if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {

                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
                    mappedAuthorities.addAll(SecurityUtils.extractAuthorityFromClaims(userAttributes));
                }
            });
            return mappedAuthorities;
        };
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers(IGNORING_SECURITY_URL);
    }
}
