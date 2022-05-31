package cn.kduck.security;

import cn.kduck.core.web.json.JsonObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 登录入口，如果当前请求的是/currentUser接口，则会以application/json方式返回失败json，
 * 否则会使用默认的登录入口处理逻辑，即302跳转到指定的登录页。
 * LiuHG
 */
public class LoginJsonAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private ObjectMapper om = new ObjectMapper();

    public LoginJsonAuthenticationEntryPoint(String loginPage) {
        super(loginPage);
    }

    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        String contextPath = request.getContextPath();
        String requestURI = request.getRequestURI();
        if(!"".equals(contextPath)){
            requestURI = requestURI.substring(contextPath.length());
        }
        if(requestURI.equals("/currentUser")){
            JsonObject jsonObject = new JsonObject("_ANONYMOUS_",-1,null);
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            om.writeValue(response.getOutputStream(),jsonObject);
        }else{
            super.commence(request,response,authException);
        }

    }

}
