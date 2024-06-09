package com.example.testsecurityjwt20240604.config;

import com.example.testsecurityjwt20240604.jwt.JWTFilter;
import com.example.testsecurityjwt20240604.jwt.JWTUtil;
import com.example.testsecurityjwt20240604.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // AuthenticationManager 을 사용하기 위해 AuthenticationConfiguration 을 의존성 주입 받아오기
    private final AuthenticationConfiguration authenticationConfiguration;
    // login 기능사용시 jwtUtil 기능을 사용하기 위해 주입 받기
    private final JWTUtil jwtUtil;


    // 비크립트 암호화 설정
    // 사용 이유는 회원 정보를 저장하고, 다시 검증 할때에
    // 비밀번호를 hash 처리 하여 암호화 한 후 검증하고 진행하게 되는데
    // 이때 필요하기 때문에 비크립트 암호화를 사용하게 된다.
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager Bean 등록 받기 위해 사용
    // 해당 메서드는 AuthenticationConfiguration 타입의 데이터를 받아야 사용가능하다.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }



    // 스프링 시큐리티 관련 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // security 에서 cors 설정
        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration configuration = new CorsConfiguration();

                                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 허용 할 프론트 주소
                                configuration.setAllowedMethods(Collections.singletonList("*")); // GET POST PUT 등 모든 http 요청 허용 하기
                                configuration.setAllowCredentials(true); // 프론트에서 credentials 설정을 해줬다면 true 로 바꿔 주어야함
                                configuration.setAllowedHeaders(Collections.singletonList("*")); // 허용 할 헤더 값들 모두 허용
                                configuration.setMaxAge(3600L); // 요청에 대해 허용할 시간

                                configuration.setExposedHeaders(Collections.singletonList("Authorization")); // 프론트에서 Authorization 를 넣은 헤더 요청도 허용

                                return configuration;
                            }
                        }));

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


        // LoginFilter 앞에 JWT Filter 를 넣어주기
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // JWT filter 작업 등록하기
        // LoginFilter 가 동작하기 위해 AuthenticationManager 메서드를 호출 하고
        // AuthenticationManager 가 작동하기 위해 authenticationConfiguration 를 의존성 주입 받아와 사용하면 된다.
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);



        // 세션 설정 -> session 의 상태를 state less 상태로 바꾸기
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // JWT 방식에서 가장 중요한 설정으로 로그인 방식을 JWT 방식으로 진행 할 예정이기 때문에 Session 설정을 state less 상태로 만들어 주어야 한다.



        return http.build();
    }
}
