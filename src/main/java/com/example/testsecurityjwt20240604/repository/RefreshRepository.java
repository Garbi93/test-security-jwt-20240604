package com.example.testsecurityjwt20240604.repository;

import com.example.testsecurityjwt20240604.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
    // refresh 토튼을 받아와 해당 refresh 토큰이 DB 에 존재 하는지 찾는 기능
    Boolean existsByRefresh(String refresh);

    // DB 에 받아온 refresh 토큰과 동일한 refresh 값을 지우기 위한 기능
    @Transactional
    void deleteByRefresh(String refresh);
}
