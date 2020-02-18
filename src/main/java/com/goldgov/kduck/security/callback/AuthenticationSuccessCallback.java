package com.goldgov.kduck.security.callback;

import com.goldgov.kduck.security.AuthUser;

/**
 * LiuHG
 */
public interface AuthenticationSuccessCallback {

    void doHandler(AuthUser user);
}
