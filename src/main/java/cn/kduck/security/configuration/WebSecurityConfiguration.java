package cn.kduck.security.configuration;

import cn.kduck.security.KduckSecurityProperties;
import cn.kduck.security.LoginJsonAuthenticationEntryPoint;
import cn.kduck.security.RoleAccessVoter;
import cn.kduck.security.authentication.KduckAuthenticationDetailsSource;
import cn.kduck.security.filter.AuthenticationFailureStrategyFilter;
import cn.kduck.security.filter.AuthenticationFailureStrategyFilter.AuthenticationFailureStrategyHandler;
import cn.kduck.security.handler.LoginFailHandler;
import cn.kduck.security.handler.LoginSuccessHandler;
import cn.kduck.security.handler.LogoutSuccessHandler;
import cn.kduck.security.oauth2.matcher.OAuthRequestMatcher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.GenericFilterBean;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

    @Autowired(required = false)
    private List<HttpSecurityConfigurer> httpSecurityConfigurerList;

    @Autowired
    private KduckAuthenticationDetailsSource authenticationDetailsSource;

    private AuthenticationFailureStrategyFilter failureStrategyHandler;

    @Value("${kduck.security.oauth2.spring-client:false}")
    private boolean isSpringClient;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<AccessDecisionVoter<? extends Object>> voterList = new ArrayList();
        voterList.add(roleAccessVoter);
//        http.requestMatcher(new OAuthRequestMatcher(new String[]{"!/oauth2/authorization/**","!/login/oauth2/**","!/userinfo","any"}));
        if(isSpringClient){
            http.requestMatcher(new OAuthRequestMatcher(new String[]{"/oauth/**","/login"}));
        }
        http.cors().and()//跨域配置生效，必须调用cors()方法
                .authorizeRequests().accessDecisionManager(new AffirmativeBased(voterList))
//                .antMatchers("/oauth2/authorization/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin()
                .successHandler(loginSuccessHandler())//配置了successHandler就不要配置defaultSuccessUrl，会被覆盖.failureHandler同理
                .failureHandler(loginFailHandler())
                .loginProcessingUrl("/login")
                .authenticationDetailsSource(authenticationDetailsSource)
                .and().logout().logoutSuccessHandler(logoutSuccessHandler()) //如果有多个登出地址对应不同的处理事件可使用defaultLogoutSuccessHandlerFor方法
                .and().csrf().disable();
        http.addFilterBefore(failureStrategyHandler, UsernamePasswordAuthenticationFilter.class);

        if(securityProperties.isHttpBasic()){
            http.httpBasic();
        }
        if(securityProperties.getLoginPage() != null){
            http.exceptionHandling().authenticationEntryPoint(new LoginJsonAuthenticationEntryPoint(securityProperties.getLoginPage()));
        }
        if(securityProperties.getAccessDeniedUrl() != null){
            http.exceptionHandling().accessDeniedPage(securityProperties.getAccessDeniedUrl());
        }

        if(httpSecurityConfigurerList != null && !httpSecurityConfigurerList.isEmpty()){
            for (HttpSecurityConfigurer securityConfigurer : httpSecurityConfigurerList) {
                securityConfigurer.configure(http);
            }
        }
//              http.authenticationProvider(new AuthenticationProvider());
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
    public LogoutSuccessHandler logoutSuccessHandler(){
        return new LogoutSuccessHandler();
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
                .antMatchers("/**/*.png","/**/*.jpg","/**/*.gif","/**/*.bmp")
                .antMatchers("/**/*.css","/**/*.js")

                .antMatchers("/swagger-ui.html")
                .antMatchers("/webjars/**")
                .antMatchers("/v2/**")
                .antMatchers("/v3/**")
                .antMatchers("/swagger-resources/**")
                .antMatchers("/error")

                .antMatchers("/favicon.ico")

                .antMatchers("/oauth/token/code")
                .antMatchers("/oauth/token/password")
                .antMatchers("/oauth/token/client")

//                .antMatchers("/actuator/health")
                .antMatchers("/actuator/**")

                .antMatchers("/proxy/**")

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

        if(securityProperties.getMfa() != null && securityProperties.getMfa().getMfaPage() != null){
            web.ignoring().antMatchers(securityProperties.getMfa().getMfaPage());
        }else{
            web.ignoring().antMatchers("/mfaPage.html");
        }

        String[] ignored = securityProperties.getIgnored();
        if(ignored != null && ignored.length > 0){
            for (String i : ignored) {
                web.ignoring().antMatchers(i);
            }
        }

        if(httpSecurityConfigurerList != null && !httpSecurityConfigurerList.isEmpty()){
            for (HttpSecurityConfigurer securityConfigurer : httpSecurityConfigurerList) {
                securityConfigurer.configure(web);
            }
        }

    }

    @Bean
    public GenericFilterBean authenticationFailureStrategyFilter(ObjectProvider<AuthenticationFailureStrategyHandler> objectProvider){
        List<AuthenticationFailureStrategyHandler> failureStrategyHandlerList = Collections.unmodifiableList(new ArrayList<>(objectProvider.stream().collect(Collectors.toList())));
        this.failureStrategyHandler = new AuthenticationFailureStrategyFilter(failureStrategyHandlerList);
        return failureStrategyHandler;
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