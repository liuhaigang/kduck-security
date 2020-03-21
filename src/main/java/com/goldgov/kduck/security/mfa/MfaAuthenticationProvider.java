package com.goldgov.kduck.security.mfa;

import com.goldgov.kduck.security.mfa.send.MfaSendStrategy;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

/**
 * MFA多因素认证提供器，该认证类会将原始UsernamePasswordAuthenticationToken对象封装到MfaAuthenticationToken对象中，用于认证过滤
 * 链针对MfaAuthenticationToken类型进行二次认证，同时在封装之前会讲二次认证的授权码生成并发送给访问者（TOTP不发送）。
 * @author LiuHG
 */
public class MfaAuthenticationProvider extends DaoAuthenticationProvider implements AuthenticationProvider {

    private MfaTokenService tokenService;
    private MfaSendStrategy sendStrategy;
    private MfaUserDetailsService userDetailsService;

    public MfaAuthenticationProvider(MfaTokenService tokenService,
                                     MfaUserDetailsService userDetailsService,
                                     MfaSendStrategy sendStrategy) {
        this.tokenService = tokenService;
        this.userDetailsService = userDetailsService;
        this.sendStrategy = sendStrategy;
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        Authentication auth = super.authenticate(authentication);
        if (auth.isAuthenticated()) {
            MfaUserDetails userDetails = userDetailsService.loadUserByUsername(auth.getName());
            if (userDetails != null) {
                String otp = tokenService.generateToken();
                if(StringUtils.hasText(otp)){
                    tokenService.addToken(auth.getName(), otp);
                    sendStrategy.send(userDetails,otp);
                }

                return new MfaAuthenticationToken(auth);
            }
        }
        return auth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}