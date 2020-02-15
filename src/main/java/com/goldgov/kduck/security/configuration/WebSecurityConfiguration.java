package com.goldgov.kduck.security.configuration;

import com.goldgov.kduck.security.*;
import com.goldgov.kduck.security.KduckSecurityProperties.AuthServer;
import com.goldgov.kduck.security.KduckSecurityProperties.Client;
import com.goldgov.kduck.security.KduckSecurityProperties.OAuth2Config;
import com.goldgov.kduck.security.KduckSecurityProperties.ResServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

/**
 * LiuHG
 */
@Configuration
@EnableConfigurationProperties(KduckSecurityProperties.class)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private RoleAccessVoter roleAccessVoter;

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        OAuth2Config oauth2Config = securityProperties.getOauth2();
        AuthServer authServer = null;
        ResServer resServer = null;
        Client client = null;
        if(oauth2Config != null){
            authServer = oauth2Config.getAuthServer();
            resServer = oauth2Config.getResServer();
            client = oauth2Config.getClient();
        }

        //如果没有配置任何客户端、资源服务器的配置，或者显示的启用了认证服务器，则触发认证配置
        //如果配置任何客户端、资源服务器的配置，又期望拥有认证服务器的功能（即完全集成认证服务），则需要显示的开启认证服务器
        if((authServer!= null && authServer.isEnabled()) ||
                (resServer== null || !resServer.isEnabled()) && client == null){
            List<AccessDecisionVoter<? extends Object>> voterList = new ArrayList();
            voterList.add(roleAccessVoter);
            http.cors().and()//跨域配置生效，必须调用cors()方法
                    .authorizeRequests().accessDecisionManager(new AffirmativeBased(voterList))
                    .anyRequest().authenticated()
                    .and().formLogin()
                    .successHandler(loginSuccessHandler())//配置了successHandler就不要配置defaultSuccessUrl，会被覆盖.failureHandler同理
                    .failureHandler(loginFailHandler())
                    .loginProcessingUrl("/login")
                    .and().csrf().disable();
            if(securityProperties.isHttpBasic()){
                http.httpBasic();
            }
            if(securityProperties.getLoginPage() != null){
                http.exceptionHandling().authenticationEntryPoint(new LoginJsonAuthenticationEntryPoint(securityProperties.getLoginPage()));
            }
            if(securityProperties.getAccessDeniedUrl() != null){
                http.exceptionHandling().accessDeniedPage(securityProperties.getAccessDeniedUrl());
            }
            //  http.authenticationProvider(new AuthenticationProvider());
        }
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler(){
        LoginSuccessHandler loginSuccessHandler = new LoginSuccessHandler();
        if(securityProperties.getDefaultSuccessUrl() != null){
            loginSuccessHandler.setDefaultTargetUrl(securityProperties.getDefaultSuccessUrl());
        }
        if(securityProperties.getSuccessUrlParameter() != null){
            loginSuccessHandler.setTargetUrlParameter(securityProperties.getSuccessUrlParameter());
        }

        loginSuccessHandler.setAlwaysUseDefaultTargetUrl(securityProperties.isAlwaysUse());
        return loginSuccessHandler;
    }

    @Bean
    public LoginFailHandler loginFailHandler(){
        LoginFailHandler loginFailHandler = new LoginFailHandler();
        if(securityProperties.getDefaultFailureUrl() != null){
            loginFailHandler.setDefaultFailureUrl(securityProperties.getDefaultFailureUrl());
        }

        loginFailHandler.setUseForward(securityProperties.isForwardToFailureUrl());

        return loginFailHandler;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/swagger-ui.html")
                .antMatchers("/webjars/**")
                .antMatchers("/v2/**")
                .antMatchers("/swagger-resources/**")
                .antMatchers("/error")

                .antMatchers("/oauth/token/code")
                .antMatchers("/oauth/token/password")
                .antMatchers("/oauth/token/client")

                .antMatchers("/actuator/health")

                //for gwt
                .antMatchers("/**/sc/**")
                .antMatchers("/**/*.nocache.js")
                .antMatchers("/**/*.cache.js");

        if(securityProperties.getLoginPage() != null){
            web.ignoring().antMatchers(securityProperties.getLoginPage());
        }
        if(securityProperties.getDefaultFailureUrl() != null){
            web.ignoring().antMatchers(securityProperties.getDefaultFailureUrl());
        }

        String[] ignored = securityProperties.getIgnored();
        if(ignored != null && ignored.length > 0){
            for (String i : ignored) {
                web.ignoring().antMatchers(i);
            }
        }

    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
