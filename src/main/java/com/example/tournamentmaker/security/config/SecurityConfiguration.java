package com.example.tournamentmaker.security.config;

import com.example.tournamentmaker.user.PermissionEnum;
import com.example.tournamentmaker.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers(HttpMethod.POST,"/api/v1/auth/**",
                        "/api/v1/auth/register/**",
                        "/api/v1/auth/refresh-token",
                        "/api/v1/auth/enable-user/**",
                        "/api/v1/auth/authenticate",
                        "/api/v1/auth/forgot-password",
                        "/api/v1/auth/reset-password")
                .permitAll()
                .requestMatchers("/api/v1/management/**").hasAnyRole(Role.ADMIN.name(), Role.MANAGER.name())
                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(PermissionEnum.ADMIN_READ.name(),
                        PermissionEnum.MANAGER_READ.name())
                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(PermissionEnum.ADMIN_CREATE.name(),
                        PermissionEnum.MANAGER_CREATE.name())
                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(PermissionEnum.ADMIN_UPDATE.name(),
                        PermissionEnum.MANAGER_UPDATE.name())
                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(PermissionEnum.ADMIN_DELETE.name(),
                        PermissionEnum.MANAGER_DELETE.name()).anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // set up the CORS configuration
                .cors(withDefaults()) // by default uses a Bean by the name of corsConfigurationSource
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                
        ;

        return http.build();
    }
    
    @Bean(name = "corsConfigurationSource")
    public CorsConfigurationSource corsConfiguration() {

        final CorsConfiguration corsConfiguration = new CorsConfiguration();


        corsConfiguration.setAllowedOriginPatterns(List.of("*"));

        corsConfiguration.setAllowedMethods(
                List.of(
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE"
                )
        );


        corsConfiguration.setAllowedHeaders(
                List.of(
                        "Authorization",
                        "Content-Type",
                        "Access-Control-Allow-Origin",
                        "Access-Control-Allow-Headers",
                        "Access-Control-Expose-Headers"
                ));

        corsConfiguration.setAllowCredentials(true);

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }
}
