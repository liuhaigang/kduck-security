package com.goldgov.kduck.security.oauth2.token.impl;

import com.goldgov.kduck.security.AuthUser;
import com.goldgov.kduck.security.oauth2.token.TokenTranslator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.util.Map;

public class DefaultTokenTranslator implements TokenTranslator {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public AuthUser translate(OAuth2AccessToken accessToken) {
        Map<String, Object> infoMap = accessToken.getAdditionalInformation();
        Object userName = infoMap.get("user_name");
        //FIXME 对于客户端认证很有可能没有用户名，userName=null
        AuthUser authUser = (AuthUser)userDetailsService.loadUserByUsername("" + userName);
        authUser.eraseCredentials();
        return authUser;
    }
}
