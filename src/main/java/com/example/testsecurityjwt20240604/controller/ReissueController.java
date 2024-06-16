package com.example.testsecurityjwt20240604.controller;

import com.example.testsecurityjwt20240604.jwt.JWTUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequiredArgsConstructor
public class ReissueController { // 해당 컨트롤러는 만료된 accessToken 을 사용할 시 refreshToken 을 갖고 새로운 accessToken 을 발급 해주는 컨트롤러 이다.

    // 새로운 토큰을 만들어주기 위해 jwtUtil 을 주입 받아준다.
    private final JWTUtil jwtUtil;

    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request,
                                     HttpServletResponse response) {
        // 재발급 받기 위해 refresh 토큰을 받기
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
            }
        }

        // 만일 받은 refresh 값이 비어 있다면
        if (refresh == null) {

            //response status code 404 오류 던지기
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

        //expired check
        // refresh 토큰 값 만료 시간 체크
        try {
            jwtUtil.isExpired(refresh);
        } catch (ExpiredJwtException e) {

            //response status code
            // 만료 되었다면 404 오류 던지기
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        // 토큰이 refresh인지 확인 (발급시 페이로드에 명시)
        String category = jwtUtil.getCategory(refresh);

        // 만일 카테고리의 값이 refresh 가 아니라면
        if (!category.equals("refresh")) {

            //response status code 404 오류 던지기
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        // 모든 검증이 완료된후 username과 role 값을 refresh 토큰으로 부터 받아오기
        String username = jwtUtil.getUsername(refresh);
        String role = jwtUtil.getRole(refresh);

        //make new JWT
        // refresh 토큰으로부터 받아온 username 과 role 값을 넣어서 새로운 accessToken 생성 해주기
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);

        //response
        // 헤더에 새로운 accessToken 셋팅해주고
        response.setHeader("access", newAccess);

        // ok 200 code 리턴 해주기
        return new ResponseEntity<>(HttpStatus.OK);
    }



}
