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

        if(callbackList != null){
            if(callbackList != null){
                for (AuthenticationFailCallback callback : callbackList) {
                    callback.doHandler(authentication,exception);
                }
            }

        }
    }
}
