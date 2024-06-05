package com.example.testsecurityjwt20240604.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 비크립트 암호화 설정
    // 사용 이유는 회원 정보를 저장하고, 다시 검증 할때에
    // 비밀번호를 hash 처리 하여 암호화 한 후 검증하고 진행하게 되는데
    // 이때 필요하기 때문에 비크립트 암호화를 사용하게 된다.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 스프링 시큐리티 관련 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // csrf disable 설정 하기
        http
                .csrf((auth) -> auth.disable());
        // -> csrf 방식을 disable 하는 이유 ?
        // 기존 session 방식으로 했을때는 session을 고정 하여 사용하는 이유로 csrf 방어를 필수적으로 해주었어야 하지만
        // JWT 방식은 session 을 state less 상태로 관리 하기 때문에 csrf 에대한 공격이 덜 위험 하다.


        // Form 로그인 방식 disable 하기
        // http basic 인증 방식 disable 하기
        http.formLogin((auth) -> auth.disable());
        http.httpBasic((auth) -> auth.disable());
        // 이 두가지를 disable 하는 이유는 JWT 방식으로 로그인을 진행 하기 때문에 위 두 기능을 막아 두었다.


        // 경로별 권한 인가 작업 하기
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 세션 설정 -> session 의 상태를 state less 상태로 바꾸기
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // JWT 방식에서 가장 중요한 설정으로 로그인 방식을 JWT 방식으로 진행 할 예정이기 때문에 Session 설정을 state less 상태로 만들어 주어야 한다.



        return http.build();
    }
}
