package com.example.testsecurityjwt20240604.jwt;

import com.example.testsecurityjwt20240604.dto.CustomUserDetails;
import com.example.testsecurityjwt20240604.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    // doFilterInternal 내부에서 JWTUtil 기능을 사용하기 위해 주입 받기
    private final JWTUtil jwtUtil;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // request 내에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 에 토큰이 담겼는지 검증 하기
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);

            // Authorization 가 비어있거나 내부 코드가 Bearer 로 시작 하지 않는 다면 메서드 종료 (필수)
            return;
        }

        System.out.println("authorization now");

        // Bearer 부분 제거 후 순수 토큰 획득하기
        String token = authorization.split(" ")[1];

        // JWT 토큰 값 내에 소멸시간 검증
        if (jwtUtil.isExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);

            // 만약 토큰 시간이 소멸 되었다면 메서드 종료 (필수)
            return;
        }

        // 최종으로 authorization 헤더값이 존재하고 토큰 값의 유효기간이 아직 유효 하다면
        // 해당 토큰을 기준으로 일시적인 session을 생성 하고 회원 값을 잠시 저장 하기

        // 토큰에서 username 과 role 값을 획득하기
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // usename 과 role 값을 userEntity 타입으로 저장하기
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 이때 비밀 번호는 사용자가 임의로 넣어줘도 괜찮다.
        userEntity.setRole(role);

        // UserDetails 에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 세션에 사용자 등록 시키기
        SecurityContextHolder.getContext().setAuthentication(authToken);

        // 모든 작업 완료후 request 와 response 에 데이터를 전달 해준다.
        filterChain.doFilter(request, response);
    }
}
