package com.goldgov.kduck.security.oauth2.token;

import com.goldgov.kduck.security.AuthUser;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * Token翻译器，用于将Token翻译成对应的认证用户对象
 */
public interface TokenTranslator {

    AuthUser translate(OAuth2AccessToken accessToken);
}
