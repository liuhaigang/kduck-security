package cn.kduck.security.handler;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

public interface OAuthTokenSuccessHandler {

    void onTokenSuccess(OAuth2AccessToken token);
}
