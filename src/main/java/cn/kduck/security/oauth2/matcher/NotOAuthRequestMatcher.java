package cn.kduck.security.oauth2.matcher;

import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class NotOAuthRequestMatcher implements RequestMatcher {

    private FrameworkEndpointHandlerMapping mapping;

    public NotOAuthRequestMatcher(FrameworkEndpointHandlerMapping mapping) {
        this.mapping = mapping;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String requestPath = getRequestPath(request);
        for (String path : mapping.getPaths()) {
            if (requestPath.startsWith(mapping.getPath(path))) {
                return false;
            }
        }
        return true;
    }

    private String getRequestPath(HttpServletRequest request) {
        String url = request.getServletPath();

        if (request.getPathInfo() != null) {
            url += request.getPathInfo();
        }

        return url;
    }
}
