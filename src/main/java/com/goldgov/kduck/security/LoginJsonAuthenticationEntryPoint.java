package com.goldgov.kduck.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LiuHG
 */
public class LoginJsonAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final String loginPage;

    private ObjectMapper om = new ObjectMapper();

    public LoginJsonAuthenticationEntryPoint(String loginPage) {
        this.loginPage = loginPage;
    }

    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        if(request.getRequestURI().equals("/currentUser")){
            JsonObject jsonObject = new JsonObject("_ANONYMOUS_",-1,null);
            response.setContentType("application/json");
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            redirectStrategy.sendRedirect(request, response, loginPage);
        }


    }

}
