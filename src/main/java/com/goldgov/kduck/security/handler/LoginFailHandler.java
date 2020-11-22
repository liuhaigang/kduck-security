package com.goldgov.kduck.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.mfa.exception.MfaValidationException;
import com.goldgov.kduck.utils.RequestUtils;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.goldgov.kduck.security.filter.AuthenticationFailureStrategyFilter.AUTHENTICATION_FAIL_STRATEGY_NAME;

/**
 * LiuHG
 */
public class LoginFailHandler extends SimpleUrlAuthenticationFailureHandler {

    private ObjectMapper om = new ObjectMapper();

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
        }else {
            failMessage = exception.getMessage();
        }

        boolean isMfa = exception instanceof MfaValidationException;

        if(RequestUtils.isAjax(request)){
            String userName = obtainUsername(request);
            String failureStrategyName = null;
            if(userName != null){
                failureStrategyName = CacheHelper.getByCacheName(AUTHENTICATION_FAIL_STRATEGY_NAME, userName,String.class);
            }

            int errorCode = -1;
            if(isMfa){
                errorCode = -3;
            }else if(failureStrategyName != null){
                errorCode = -2;
            }

            JsonObject jsonObject = new JsonObject(null,errorCode ,failMessage);
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            super.onAuthenticationFailure(request,response,exception);
        }
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY);
    }

}
