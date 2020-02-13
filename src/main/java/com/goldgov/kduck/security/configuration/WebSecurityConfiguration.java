package com.goldgov.kduck.security.configuration;

import com.goldgov.kduck.security.*;
import com.goldgov.kduck.security.KduckSecurityProperties.AuthServer;
import com.goldgov.kduck.security.KduckSecurityProperties.Client;
import com.goldgov.kduck.security.KduckSecurityProperties.ResServer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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
        AuthServer authServer = securityProperties.getAuthServer();
        ResServer resServer = securityProperties.getResServer();
        Client client = securityProperties.getClient();
        //如果没有配置任何客户端、资源服务器的配置，或者显示的启用了认证服务器，则触发认证配置
        //如果配置任何客户端、资源服务器的配置，又期望拥有认证服务器的功能（即完全集成认证服务），则需要显示的开启认证服务器
        if((authServer!= null && authServer.isEnabled()) ||
                (resServer== null || !resServer.isEnabled()) && client == null){
            List<AccessDecisionVoter<? extends Object>> voterList = new ArrayList();
            voterList.add(roleAccessVoter);
            http.cors().and()//跨域配置生效，必须调用cors()方法
                    .authorizeRequests().accessDecisionManager(new AffirmativeBased(voterList))
                    .anyRequest().authenticated()
//                .antMatchers("/login").permitAll()
                    .and().httpBasic()
                    .and().formLogin()
                    .successHandler(loginSuccessHandler())
                    .failureHandler(loginFailHandler())
                    .loginProcessingUrl("/login")
                    .and().exceptionHandling()
                    .authenticationEntryPoint(new LoginJsonAuthenticationEntryPoint("/index.html"))
                    .and().csrf().disable();
            //        http.authenticationProvider(new AuthenticationProvider());
        }
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler(){
        return new LoginSuccessHandler();
    }

    @Bean
    public LoginFailHandler loginFailHandler(){
        return new LoginFailHandler();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/swagger-ui.html")
                .antMatchers("/webjars/**")
                .antMatchers("/v2/**")
                .antMatchers("/swagger-resources/**")
                .antMatchers("/error")
                .antMatchers("/index.html")

                .antMatchers("/oauth/login")

                .antMatchers("/actuator/health")

                //for gwt
                .antMatchers("/**/sc/**")
                .antMatchers("/**/*.nocache.js")
                .antMatchers("/**/*.cache.js");

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
