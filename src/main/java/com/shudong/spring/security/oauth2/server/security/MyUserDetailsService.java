package com.shudong.spring.security.oauth2.server.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@RequiredArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (Objects.equals("admin", username)) {
            return User.builder()
                .username(username)
                .password(passwordEncoder.encode("password"))
                .authorities("ROLE_ADMIN", "ROLE_USER")
                .build();
        } else if (Objects.equals("shudong", username)) {
            return User.builder()
                .username(username)
                .password(passwordEncoder.encode("password"))
                .authorities("ROLE_USER")
                .build();
        }
        throw new UsernameNotFoundException(String.format("Username[%s] not found", username));
    }
}