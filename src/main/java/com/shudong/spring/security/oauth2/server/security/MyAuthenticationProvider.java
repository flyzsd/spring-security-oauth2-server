package com.shudong.spring.security.oauth2.server.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();

        if ("admin".equals(name) && "password".equals(password)) {
            return new UsernamePasswordAuthenticationToken(name, password, AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_ADMIN"));
        } else if ("shudong".equals(name) && "password".equals(password)) {
            return new UsernamePasswordAuthenticationToken(name, password, AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));
        } else {
            throw new BadCredentialsException("External system authentication failed");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return Objects.equals(UsernamePasswordAuthenticationToken.class, authentication);
    }
}
