package cn.kduck.security.mfa.impl;

import cn.kduck.core.cache.CacheHelper;
import cn.kduck.security.mfa.MfaTokenService;
import cn.kduck.security.mfa.MfaType;
import cn.kduck.security.mfa.MfaUserDetails;
import cn.kduck.security.mfa.generator.OtpGenerator;
import cn.kduck.security.mfa.generator.impl.DefaultOtpGeneratorImpl;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

public class MfaTokenServiceImpl implements MfaTokenService {

    private String MFA_TOKEN_SUFFIX = ".MFA_TOKEN_SUFFIX";

    private final MfaType type;

    private OtpGenerator otpGenerator = new DefaultOtpGeneratorImpl(6);

    private GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

    public MfaTokenServiceImpl(MfaType type){
        this.type = type;
    }

    @Override
    public void addToken(String username, String token) {
        CacheHelper.put(username + MFA_TOKEN_SUFFIX,token,3600);
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
            String cachedToken = CacheHelper.get(mfaUserDetails.getUsername() + MFA_TOKEN_SUFFIX,String.class);
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
