package com.goldgov.kduck.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.utils.RequestUtils;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LiuHG
 */
public class LoginJsonAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private ObjectMapper om = new ObjectMapper();

    public LoginJsonAuthenticationEntryPoint(String loginPage) {
        super(loginPage);
    }

    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        if(request.getRequestURI().equals("/currentUser")){
            JsonObject jsonObject = new JsonObject("_ANONYMOUS_",-1,null);
            response.setContentType("application/json");
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            super.commence(request,response,authException);
        }

    }

}
