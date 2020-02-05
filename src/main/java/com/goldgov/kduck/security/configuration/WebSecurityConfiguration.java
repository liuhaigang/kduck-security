package com.goldgov.kduck.security.configuration;

import com.goldgov.kduck.security.LoginFailHandler;
import com.goldgov.kduck.security.LoginJsonAuthenticationEntryPoint;
import com.goldgov.kduck.security.LoginSuccessHandler;
import com.goldgov.kduck.security.RoleAccessVoter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
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
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private RoleAccessVoter roleAccessVoter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<AccessDecisionVoter<? extends Object>> voterList = new ArrayList();
        voterList.add(roleAccessVoter);
//        voterList.add(new UnlimitAccessVoter());
        http.cors().and()//跨域配置生效，必须调用cors()方法
                .authorizeRequests().accessDecisionManager(new AffirmativeBased(voterList))
//                .anyRequest().authenticated()
//                .antMatchers("/webjars/**","/swagger-resources/**","/swagger-ui.html/**").permitAll()
                .anyRequest().authenticated()
//                .accessDecisionManager(new AffirmativeBased(voterList))
                .and()
                .formLogin()
                .successHandler(loginSuccessHandler())
                .failureHandler(loginFailHandler())
                .and().exceptionHandling().authenticationEntryPoint(new LoginJsonAuthenticationEntryPoint("/index.html"))
//                .failureHandler(new AuthenticationFailureHandler(){
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        response.getWriter().write("login error!");
//                    }
//                });
                .and()
                .csrf().disable();
//                .loginProcessingUrl()
//                .loginPage("/login")
//                .defaultSuccessUrl("/main")
//        http.authorizeRequests().antMatchers("/**").access("IS_AUTHENTICATED_ANONYMOUSLY");
    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(authenticationProvider());
//    }

//    @Bean
//    public AuthenticationProvider authenticationProvider(){
//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        authenticationProvider.setUserDetailsService(new UserDetailsServiceImpl());
//
//        return authenticationProvider;
//    }


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

                //for gwt
                .antMatchers("/**/sc/**")
                .antMatchers("/**/*.nocache.js")
                .antMatchers("/**/*.cache.js");
    }


    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
