package com.goldgov.kduck.security.mfa;

public interface MfaUserDetailsService {

    boolean isEnabled(String username);

    MfaUserDetails loadUserByUsername(String username);

}
