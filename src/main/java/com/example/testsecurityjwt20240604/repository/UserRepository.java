package com.example.testsecurityjwt20240604.repository;

import com.example.testsecurityjwt20240604.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

}
