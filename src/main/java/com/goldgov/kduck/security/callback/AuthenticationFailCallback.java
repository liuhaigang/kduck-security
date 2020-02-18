package com.goldgov.kduck.security.callback;

import org.springframework.security.core.Authentication;

/**
 * LiuHG
 */
public interface AuthenticationFailCallback {

    void doHandler(Authentication authentication,Exception exception);
}
