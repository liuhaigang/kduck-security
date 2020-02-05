package com.goldgov.kduck.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LiuHG
 */
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper om = new ObjectMapper();

    @Autowired(required = false)
    private LoginSuccessCallback callback;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        AuthUser principal = (AuthUser)authentication.getPrincipal();
        principal.setLoginIp(request.getRemoteAddr());
        if(callback != null){
            callback.doHandler(principal);
        }
        JsonObject jsonObject = new JsonObject(principal.getUsername());
        response.setContentType("application/json");
        om.writeValue(response.getOutputStream(),jsonObject);
    }
}
