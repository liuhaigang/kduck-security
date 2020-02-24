package com.goldgov.kduck.security.listener;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.callback.AuthenticationFailCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AuthenticationFailListener implements ApplicationListener<AbstractAuthenticationFailureEvent> {

    public static final String AUTHENTICATION_FAIL_CAHCE_NAME = "AUTHENTICATION_FAIL_CAHCE_NAME";

    @Autowired(required = false)
    private List<AuthenticationFailCallback> callbackList;

    @Override
    public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
        AuthenticationException exception = event.getException();
        Authentication authentication = event.getAuthentication();

        int badCredentialCount = 0;
        if(authentication instanceof UsernamePasswordAuthenticationToken &&
                exception instanceof BadCredentialsException){
            String accountName = authentication.getName();
            badCredentialCount = increase(accountName);
        }

        if(callbackList != null){
            for (AuthenticationFailCallback callback : callbackList) {
                callback.doHandle(authentication,exception,badCredentialCount);
            }
        }
    }

    private int increase(String accountName){
        Integer count = CacheHelper.getByCacheName(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,Integer.class);
        count = count == null ? 1 : ++count;
        CacheHelper.put(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,count,600);//FIXME seconds to config
        return count;
    }

    @Component
    public static class AuthenticationSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {
        @Override
        public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
            Authentication authentication = event.getAuthentication();
            if(authentication instanceof UsernamePasswordAuthenticationToken){
                CacheHelper.evict(AUTHENTICATION_FAIL_CAHCE_NAME,authentication.getName());
            }
        }
    }
}
