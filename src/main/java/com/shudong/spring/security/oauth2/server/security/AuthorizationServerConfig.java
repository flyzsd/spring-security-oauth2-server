package com.shudong.spring.security.oauth2.server.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@RequiredArgsConstructor
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    private static final String CLIEN_ID = "oauth2-client-id";
    private static final String CLIENT_SECRET = "oauth2-client-secret";
    private static final String RESOURCE_ID = "oauth2_resource_id";
    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String SCOPE_READ = "read";
    private static final String SCOPE_WRITE = "write";
    private static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1 * 60 * 60;
    private static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 24 * 60 * 60;

    private final MyUserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    /**
     * Configure the ClientDetailsService, declaring individual clients and their properties.
     *
     * @param configurer
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
        configurer.inMemory()
            .withClient(CLIEN_ID)
            .secret(passwordEncoder.encode(CLIENT_SECRET))
            .resourceIds(RESOURCE_ID)
            .authorities("ROLE_TRUSTED_CLIENT")
            .scopes(SCOPE_READ, SCOPE_WRITE)
            .authorizedGrantTypes(GRANT_TYPE_PASSWORD, REFRESH_TOKEN)
            .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
            .refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS);
    }

    /**
     * Configure the non-security features of the Authorization Server endpoints, like token store, token customizations, user approvals and grant types.
     *
     * @param endpoints
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
            .tokenStore(new JwtTokenStore(jwtAccessTokenConverter))
            .accessTokenConverter(jwtAccessTokenConverter)
            .userDetailsService(userDetailsService)
            .authenticationManager(authenticationManager);
    }

    /**
     * Configure the security of the Authorization Server, which means in practical terms the /oauth/token endpoint.
     *
     * @param oauthServer
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        //allowing access to the token only for clients with 'ROLE_TRUSTED_CLIENT' authority
        oauthServer
            .tokenKeyAccess("hasAuthority('ROLE_TRUSTED_CLIENT')")          //for /oauth/token_key endpoint
            .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");       //for /oauth/check_token endpoint
    }
}
