package com.goldgov.kduck.security.callback;

import org.springframework.security.core.Authentication;

/**
 * LiuHG
 */
public interface AuthenticationFailCallback {

    void doHandle(Authentication authentication, Exception exception,int badCredentialCount);
}
