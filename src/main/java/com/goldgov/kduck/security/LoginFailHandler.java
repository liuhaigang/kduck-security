package com.goldgov.kduck.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LiuHG
 */
public class LoginFailHandler implements AuthenticationFailureHandler {

    private ObjectMapper om = new ObjectMapper();

    @Autowired(required = false)
    private LoginFailCallback callback;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String failMessage =  null;
        if(exception instanceof BadCredentialsException){
            failMessage = "登录失败，请检查你的用户名或密码是否正确";
        }else if(exception instanceof DisabledException){
            failMessage = "登录失败，用户已失效";
        }else if(exception instanceof LockedException){
            failMessage = "登录失败，用户已被锁定";
        }else if(exception instanceof AccountExpiredException){
           failMessage = "登录失败，用户帐号已过期";
        }else if(exception instanceof CredentialsExpiredException){
            failMessage = "登录失败，帐号密码已过期";
        }

        if(callback != null){
            callback.doHandler(exception);
        }

        JsonObject jsonObject = new JsonObject(null,-1,failMessage);
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        om.writeValue(response.getOutputStream(),jsonObject);
    }
}
