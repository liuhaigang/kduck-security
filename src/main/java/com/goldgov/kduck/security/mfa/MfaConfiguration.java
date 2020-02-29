package com.goldgov.kduck.security.mfa;

import com.goldgov.kduck.security.KduckSecurityProperties;
import com.goldgov.kduck.security.KduckSecurityProperties.MfaConfig;
import com.goldgov.kduck.security.configuration.HttpSecurityConfigurer;
import com.goldgov.kduck.security.mfa.impl.MfaTokenServiceImpl;
import com.goldgov.kduck.security.mfa.impl.MfaUserDetailsServiceImpl;
import com.goldgov.kduck.security.mfa.send.MfaSendStrategy;
import com.goldgov.kduck.security.mfa.send.impl.StdOutSendStrategy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

@Configuration
@ConditionalOnProperty(prefix = "kduck.security.mfa",name = "enabled",havingValue = "true")
public class MfaConfiguration implements HttpSecurityConfigurer {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        String validateUrl = "/mfa/validate";
        String mfaPage = "/mfaPage.html";
        String successUrl = "/";

        if(StringUtils.hasText(securityProperties.getDefaultSuccessUrl())){
            successUrl = securityProperties.getDefaultSuccessUrl();
        }

        MfaConfig mfaConfig = securityProperties.getMfa();
        if(mfaConfig != null){
            if(StringUtils.hasText(mfaConfig.getValidateUrl())){
                validateUrl = mfaConfig.getValidateUrl();
            }

            if(StringUtils.hasText(mfaConfig.getMfaPage())){
                mfaPage = mfaConfig.getMfaPage();
            }
        }

        http.authenticationProvider(mfaAuthenticationProvider());
        http.addFilterAfter(new MfaAuthenticationValidationFilter(
                mfaUserDetailsService(),
                mfaTokenService(),validateUrl, successUrl, mfaPage
        ), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {

    }

    @Bean
    public MfaAuthenticationProvider mfaAuthenticationProvider(){
        MfaAuthenticationProvider mfaProvider = new MfaAuthenticationProvider(
                mfaTokenService(),
                mfaUserDetailsService(),
                mfaAuthenticationStrategy());

        mfaProvider.setUserDetailsService(userDetailsService);
        mfaProvider.setPasswordEncoder(passwordEncoder);
        return mfaProvider;
    }

//    @Bean
//    public MfaAuthenticatorService MfaAuthenticatorService(MfaUserDetailsService mfaUserDetailsService){
//        return new MfaAuthenticatorService(mfaUserDetailsService);
//    }

    @Bean
    @ConditionalOnMissingBean(MfaUserDetailsService.class)
    public MfaUserDetailsService mfaUserDetailsService(){
        MfaUserDetailsServiceImpl mfaUserDetailsService = new MfaUserDetailsServiceImpl();

        if(securityProperties.getMfa() != null && securityProperties.getMfa().getMfaUsers() != null){
            String[] mfaUsers = securityProperties.getMfa().getMfaUsers();
            for (String mfaUser : mfaUsers) {
                String[] split = mfaUser.split(":");
                Assert.isTrue(split.length==2,"多因素认证用户格式不正确，正确格式（冒号分隔）：username:secret");
                mfaUserDetailsService.addMfaUser(split[0],split[1]);
            }
        }

        return mfaUserDetailsService;
    }

    @Bean
    @ConditionalOnMissingBean(MfaTokenService.class)
    public MfaTokenService mfaTokenService(){
        MfaType type = MfaType.TOTP;
        if(securityProperties.getMfa() != null && securityProperties.getMfa().getType() != null){
            type = MfaType.valueOf(securityProperties.getMfa().getType().toUpperCase());
        }
        return new MfaTokenServiceImpl(type);
    }

    @Bean
    @ConditionalOnMissingBean(MfaSendStrategy.class)
    public MfaSendStrategy mfaAuthenticationStrategy(){
        return new StdOutSendStrategy();
    }
}
