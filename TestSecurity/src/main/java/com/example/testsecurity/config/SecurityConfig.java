package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/join-proc").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/login-proc")
                        .permitAll()
                );

        http
                .csrf((auth) -> auth.disable());

        // 중복 로그인 컨르롤
        http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)
                );

        // 세션 고정 공격 방지
        http
                .sessionManagement((auth) -> auth
                        .sessionFixation().changeSessionId()
                );

        return http.build();
    }
}
