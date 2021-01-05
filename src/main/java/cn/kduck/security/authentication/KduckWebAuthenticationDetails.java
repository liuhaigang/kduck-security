package cn.kduck.security.authentication;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class KduckWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String loginType;

    public KduckWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        loginType = request.getParameter("loginType");
    }

    public String getLoginType() {
        return loginType;
    }

}
