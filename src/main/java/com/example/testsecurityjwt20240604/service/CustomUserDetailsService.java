package com.example.testsecurityjwt20240604.service;

import com.example.testsecurityjwt20240604.dto.CustomUserDetails;
import com.example.testsecurityjwt20240604.entity.UserEntity;
import com.example.testsecurityjwt20240604.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    // 회원 DB 관련 repository 기능을 생성자 주입 받기
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // userRepository 의 findByUsername 기능으로 DB 에 회원 이름으로 된 정보가 존재하는 지 찾기
        UserEntity userData = userRepository.findByUsername(username);

        // 만일 DB에 회원 정보가 존재한다면 CustomUserDetails 에 회원 정보 전달하기
        if (userData != null) {
            return new CustomUserDetails(userData);
        }

        return null;
    }
}
