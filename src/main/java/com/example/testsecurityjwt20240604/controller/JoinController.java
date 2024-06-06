package com.example.testsecurityjwt20240604.controller;

import com.example.testsecurityjwt20240604.dto.JoinDTO;
import com.example.testsecurityjwt20240604.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    // 회원 가입 로직
    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        joinService.joinProcess(joinDTO);

        return "ok";
    }
}
