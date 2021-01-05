package cn.kduck.security.oauth2.matcher;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;

public class OAuthRequestMatcher implements RequestMatcher {

    private final String[] paths;

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    public OAuthRequestMatcher(String[] paths){
        this.paths = paths;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String requestPath = getRequestPath(request);
        for (String path : paths) {
            if(path.startsWith("!") && antPathMatcher.match(path.substring(1),requestPath)) {
                return false;
            }

            if (path.equals("any") || antPathMatcher.match(path,requestPath)) {
                return true;
            }
        }
        return false;
    }

    private String getRequestPath(HttpServletRequest request) {
        String url = request.getServletPath();

        if (request.getPathInfo() != null) {
            url += request.getPathInfo();
        }

        return url;
    }
}
