package com.goldgov.kduck.security.mfa.send.impl;

import com.goldgov.kduck.security.mfa.MfaUserDetails;
import com.goldgov.kduck.security.mfa.send.MfaSendStrategy;

/**
 * just for test
 * @author LiuHG
 */
public class StdOutSendStrategy implements MfaSendStrategy {
    @Override
    public String sendType() {
        return "sysout";
    }

    @Override
    public void send(MfaUserDetails userDetails, String otp) {
        System.out.println("*** MFA *** :"+otp);
    }
}
