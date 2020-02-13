package com.goldgov.kduck.security.oauth2.configuration;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Map;

public interface JwtTokenExtInfo {

    Map<String, Object> extInfo(OAuth2AccessToken accessToken, OAuth2Authentication authentication);
}
