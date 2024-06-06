package com.example.testsecurityjwt20240604.service;

import com.example.testsecurityjwt20240604.dto.JoinDTO;
import com.example.testsecurityjwt20240604.entity.UserEntity;
import com.example.testsecurityjwt20240604.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor // final 필드와 @NonNull 필드를 매개변수로 받는 생성자를 자동으로 생성 하는 기능
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // 회원 가입 기능
    public void joinProcess(JoinDTO joinDTO) {
        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        // 동일한 회원 정보가 있는지 DB 먼저 점검해보기
        Boolean isExist = userRepository.existsByUsername(username);

        // 만일 동일한 회원 정보가 존재하면 가입 중지
        if (isExist) {
            return;
        }

        // 만일 동일한 정보가 없다면 가입 진행 시키기
        // UserEntity 타입으로 JPA 가 인식 하기 때문에 Entity 타입으로 회원 정보 넣어주기
        UserEntity data = new UserEntity();
        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
