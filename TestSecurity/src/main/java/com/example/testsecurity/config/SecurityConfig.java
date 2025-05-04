package com.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
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

    /**
     * Role Hierarchy (계층 권한)
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        /*RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");

        return roleHierarchy;*/

        /*return RoleHierarchyImpl.fromHierarchy("""
                ROLE_ADMIN > ROLE_USER
                """);*/

        return RoleHierarchyImpl.withDefaultRolePrefix()
                .role("ADMIN").implies("USER")
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login", "/join", "/join-proc").permitAll()
                        .requestMatchers("/my/**").hasAnyRole("USER")
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                        .loginProcessingUrl("/login-proc")
                        .permitAll()
                );
        /*// HTTP Basic 방식 로그인 인증
        http
                .httpBasic(Customizer.withDefaults());*/

//        http
//                .csrf((auth) -> auth.disable());

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

        // GET 방식 로그아웃
        http
                .logout((auth) -> auth.logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                );

        return http.build();
    }
}
