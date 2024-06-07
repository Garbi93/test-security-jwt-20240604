package com.example.testsecurityjwt20240604.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

// JWT 필터를 만들고 servlet 의 필터를 가로채 넣어놓기 위해 만들다
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager 를 사용하기 위해서는 주입 받아야한다.
    private final AuthenticationManager authenticationManager;

    // JWT 회원 검증 로직
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 클라이언트 요청에서 username, password 정보를 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username = " + username);

        // 스프링 시큐리티에 username 과 password를 검증하기 위 token 형식으로 담아야 한다.
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // token 형식으로 담은 데이터를 검증을 위핸 AuthenticationManager 로 전달
        // AuthenticationManager 를 사용하기 위해서는 주입 받아야한다.
        return authenticationManager.authenticate(authToken);
    }

    // 회원 검증 성공시 로직
    // 성공하면 JWT 를 발급해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

    }


    // JWT 회원 검증 실패시 로직
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {

    }


}
