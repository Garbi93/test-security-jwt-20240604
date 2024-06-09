package com.example.testsecurityjwt20240604.dto;

import com.example.testsecurityjwt20240604.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    // 생성자 방식으로 회원 entity 를 주입 받아야한다.
    private final UserEntity userEntity;

    // Role 값을 반환하는기능
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Collection 타입의 빈 객체를 만들어주고
        Collection<GrantedAuthority> collection = new ArrayList<>();

        // 빈 객체 안에 userEntity 로부터 Role 값을 받아 collection 에 저장
        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return userEntity.getRole();
            }
        });

        // 저장한 값을 반환 한다.
        return collection;
    }


    // password 를 반환 하는 기능
    @Override
    public String getPassword() {
        return userEntity.getPassword();
    }

    // 회원 이름을 반환 하는 기능
    @Override
    public String getUsername() {
        return userEntity.getUsername();
    }

    // 계정이 초과 되었는지?
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겼는지?
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
