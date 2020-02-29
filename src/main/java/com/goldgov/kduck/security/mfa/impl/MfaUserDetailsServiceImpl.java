package com.goldgov.kduck.security.mfa.impl;

import com.goldgov.kduck.security.mfa.MfaUserDetails;
import com.goldgov.kduck.security.mfa.MfaUserDetails.SimpleMfaUserDetails;
import com.goldgov.kduck.security.mfa.MfaUserDetailsService;

import java.util.HashMap;
import java.util.Map;

public class MfaUserDetailsServiceImpl implements MfaUserDetailsService {

    private static final Map<String, String> SECRET_BY_USERNAME = new HashMap<>();
    static{
        SECRET_BY_USERNAME.put("liuhg", "JBSWY3DPEHPK3PXP");
    }

    @Override
    public boolean isEnabled(String username) {
        return SECRET_BY_USERNAME.containsKey(username);
    }

    @Override
    public MfaUserDetails loadUserByUsername(String username){
        if(SECRET_BY_USERNAME.containsKey(username)){
            SimpleMfaUserDetails simpleMfaUserDetails = new SimpleMfaUserDetails();
            simpleMfaUserDetails.setUsername(username);
            simpleMfaUserDetails.setSecret(SECRET_BY_USERNAME.get(username));
            return simpleMfaUserDetails;
        }
        return null;
    }
}
