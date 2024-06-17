package com.example.testsecurityjwt20240604.jwt;

import com.example.testsecurityjwt20240604.dto.CustomUserDetails;
import com.example.testsecurityjwt20240604.entity.RefreshEntity;
import com.example.testsecurityjwt20240604.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

// JWT 필터를 만들고 servlet 의 필터를 가로채 넣어놓기 위해 만들다
// 로그인 관련 기능 class
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager 를 사용하기 위해서는 주입 받아야한다.
    private final AuthenticationManager authenticationManager;

    // JWT 관련 기능을 사용 하기 위해 주입 받기
    private final JWTUtil jwtUtil;

    // refresh 토큰의 DB 관련 기능을 사용하기 위해 주입 받기
    private final RefreshRepository refreshRepository;

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
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication){

//        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
//
//        // 회원 이름 받아오기
//        String username = customUserDetails.getUsername();
//
//        // role 값 받는 과정
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//
//        // role 값 받아오기
//        String role = auth.getAuthority();
//
//        // username 정보과 role 값을 갖고 jwtUtil 의 createJwt 기능을 요청 (요청 할때에 만료 시간도 넣어준다.)
//        String token = jwtUtil.createJwt(username, role, 60*60*10L);
//
//        // token 값을 프론트에 응답 해주기
//        response.addHeader("Authorization", "Bearer " + token);

        // accessToken refreshToken 발급 해주기 위한 로직
        // 유저 정보 username, role 값 받아오기
        String username = authentication.getName();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 유저로부터 받아온 username, role 값을 기준으로 토큰 생성
        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        // 생성된 refresh token 을 DB 에 저장
        addRefreshEntity(username, refresh, 86400000L);

        // 토큰 발급 받은후 응답 설정
        response.setHeader("access", access); // 헤더에 access 저장
        response.addCookie(createCookie("refresh", refresh)); // 쿠키에 refresh 저장
        response.setStatus(HttpStatus.OK.value()); // 상태코드 발급
    }




    // JWT 회원 검증 실패시 로직
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        // 로그인 실패시 401 응답 보내기
        response.setStatus(401);
    }


    // refreshToken 을 우리 DB 에 저장 시키는 메서드
    private void addRefreshEntity(String username,
                                  String refresh,
                                  Long expiredMs) {
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        // refresh token 을 저장 시켜주기
        refreshRepository.save(refreshEntity);
    }




    // createCookie 메서드
    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        //cookie.setSecure(true);
        //cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }


}
