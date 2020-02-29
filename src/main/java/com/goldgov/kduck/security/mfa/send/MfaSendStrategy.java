package com.goldgov.kduck.security.mfa.send;

import com.goldgov.kduck.security.mfa.MfaUserDetails;

public interface MfaSendStrategy {

    String sendType();

    void send(MfaUserDetails userDetails, String otp);
}
