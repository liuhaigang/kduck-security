package com.goldgov.kduck.security.mfa.impl;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.mfa.MfaTokenService;
import com.goldgov.kduck.security.mfa.MfaType;
import com.goldgov.kduck.security.mfa.MfaUserDetails;
import com.goldgov.kduck.security.mfa.generator.OtpGenerator;
import com.goldgov.kduck.security.mfa.generator.impl.DefaultOtpGeneratorImpl;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

public class MfaTokenServiceImpl implements MfaTokenService {

    private final MfaType type;

    private OtpGenerator otpGenerator = new DefaultOtpGeneratorImpl(6);

    private GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

    public MfaTokenServiceImpl(MfaType type){
        this.type = type;
    }

    @Override
    public void addToken(String username, String token) {
        CacheHelper.put(username,token,3600);
    }

    @Override
    public boolean isTokenValid(MfaUserDetails mfaUserDetails, String token) {
        if(type == MfaType.TOTP){
            int totpPassword = googleAuthenticator.getTotpPassword(mfaUserDetails.getSecret());
            int tokenCode;
            try {
                tokenCode =  Integer.parseInt(token);
            } catch (NumberFormatException e) {
                throw new InvalidGrantException("Invalid MFA code");
            }
            return totpPassword == tokenCode;
        }else if(type == MfaType.CODE){
            String cachedToken = CacheHelper.get(mfaUserDetails.getUsername(),String.class);
            if(cachedToken == null) {
                throw new RuntimeException("用户令牌不存在或已过期：" + mfaUserDetails.getUsername());
            }
            cachedToken = cachedToken.toUpperCase();
            return cachedToken.equals(token.toUpperCase());
        }
        throw new RuntimeException("不支持的MFA令牌类型" + type);
    }

    @Override
    public String generateToken() {
        if(type == MfaType.TOTP){
            return null;
        }
        return otpGenerator.generateToken();
    }
}
