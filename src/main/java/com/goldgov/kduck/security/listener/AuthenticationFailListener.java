package com.goldgov.kduck.security.listener;

import com.goldgov.kduck.security.callback.AuthenticationFailCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthenticationFailListener implements ApplicationListener<AbstractAuthenticationFailureEvent> {

    @Autowired(required = false)
    private List<AuthenticationFailCallback> callbackList;

    @Override
    public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
        AuthenticationException exception = event.getException();
        Authentication authentication = event.getAuthentication();
//        String failMessage =  null;
//        if(exception instanceof BadCredentialsException){
//            failMessage = "登录失败，请检查你的用户名或密码是否正确";
//        }else if(exception instanceof DisabledException){
//            failMessage = "登录失败，用户已失效";
//        }else if(exception instanceof LockedException){
//            failMessage = "登录失败，用户已被锁定";
//        }else if(exception instanceof AccountExpiredException){
//            failMessage = "登录失败，用户帐号已过期";
//        }else if(exception instanceof CredentialsExpiredException){
//            failMessage = "登录失败，帐号密码已过期";
//        }

        if(callbackList != null){
            if(callbackList != null){
                for (AuthenticationFailCallback callback : callbackList) {
                    callback.doHandler(authentication,exception);
                }
            }

        }
    }
}
