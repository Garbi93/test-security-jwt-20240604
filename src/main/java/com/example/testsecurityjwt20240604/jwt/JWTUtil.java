package com.example.testsecurityjwt20240604.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    // JWT 암호화 객체 키 생성
    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 검증을 진행할 getUsername, getRole, isExpired 기능
    // getUsername 는 회원 아이디 검증
    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    // getRole 은 Role 값 검증
    public String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // isExpired 는 만료 시간 검증
    public Boolean isExpired(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }


    //  토큰을 생성하는 기능
    public String createJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 현재 발행시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 해당 토큰이 소멸 되는 시간
                .signWith(secretKey) // 암호화 규칙인 secretKey 넣어주기
                .compact(); // 마지막으로 compact 시켜주기
    }

}
