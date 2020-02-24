package com.goldgov.kduck.security.callback;


import org.springframework.security.core.userdetails.UserDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * LiuHG
 */
public interface AuthenticationSuccessCallback {

    void doHandle(UserDetails user, HttpServletRequest request);
}
