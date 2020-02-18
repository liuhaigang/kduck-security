package com.goldgov.kduck.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.security.AuthUser;
import com.goldgov.kduck.utils.RequestUtils;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * LiuHG
 */
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private ObjectMapper om = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        AuthUser principal = (AuthUser)authentication.getPrincipal();

        if(RequestUtils.isAjax(request)){
            JsonObject jsonObject = new JsonObject(principal.getUsername());
            response.setContentType("application/json");
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            super.onAuthenticationSuccess(request,response,authentication);
        }
    }

}
