package com.goldgov.kduck.security.listener;

import com.goldgov.kduck.security.callback.AuthenticationSuccessCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component
public class AuthenticationSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {

    @Autowired(required = false)
    private List<AuthenticationSuccessCallback> callbackList;

    @Override
    public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();

        Authentication authentication = event.getAuthentication();
        Object principal = authentication.getPrincipal();
        User authUser;
        if(principal instanceof User){
            authUser = (User) principal;
        } else {
            throw new RuntimeException("未知认证对象：" + principal);
        }
        authUser.eraseCredentials();
        if(callbackList != null){
            for (AuthenticationSuccessCallback callback : callbackList) {
                callback.doHandle(authUser,request);
            }
        }
    }
}
