package com.shudong.spring.security.oauth2.server.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Slf4j
@RestController
@RequestMapping("/user")
public class UserController {
    @RequestMapping("/")
    public Principal user(Principal principal) {
        if(principal instanceof Authentication) {
            Authentication authentication = (Authentication) principal;
            log.info("authentication.getPrincipal = {}", authentication.getPrincipal());
        }
        return principal;
    }
}