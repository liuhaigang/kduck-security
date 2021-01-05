package cn.kduck.security.handler;

import cn.kduck.security.listener.AuthenticationFailListener;
import com.fasterxml.jackson.databind.ObjectMapper;
import cn.kduck.core.cache.CacheHelper;
import cn.kduck.core.utils.RequestUtils;
import cn.kduck.core.web.json.JsonObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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

        if(authentication instanceof UsernamePasswordAuthenticationToken){
            CacheHelper.evict(AuthenticationFailListener.AUTHENTICATION_FAIL_CAHCE_NAME,authentication.getName());
        }

        if(RequestUtils.isAjax(request)){
            JsonObject jsonObject = new JsonObject(authentication.getName());
            response.setContentType("application/json");
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            super.onAuthenticationSuccess(request,response,authentication);
        }
    }

}
