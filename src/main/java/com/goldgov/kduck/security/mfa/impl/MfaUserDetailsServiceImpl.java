package com.goldgov.kduck.security.mfa.impl;

import com.goldgov.kduck.security.mfa.MfaUserDetails;
import com.goldgov.kduck.security.mfa.MfaUserDetails.SimpleMfaUserDetails;
import com.goldgov.kduck.security.mfa.MfaUserDetailsService;

import java.util.HashMap;
import java.util.Map;

/**
 * 简单的多因素认证用户实现，用户信息从配置文件中获取，仅包含用户名及TOTP的密钥，即仅能用于TOTP方式的多因素认证
 * @author LiuHG
 */
public class MfaUserDetailsServiceImpl implements MfaUserDetailsService {

    private static final Map<String, String> SECRET_BY_USERNAME = new HashMap<>();

//    static{
//        SECRET_BY_USERNAME.put("liuhg", "JBSWY3DPEHPK3PXP");
//    }

    public void addMfaUser(String username,String secret){
        SECRET_BY_USERNAME.put(username,secret);
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
