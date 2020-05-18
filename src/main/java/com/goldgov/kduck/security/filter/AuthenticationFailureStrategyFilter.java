package com.goldgov.kduck.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.exception.AuthenticationFailureException;
import com.goldgov.kduck.security.listener.AuthenticationFailListener;
import com.goldgov.kduck.security.listener.AuthenticationFailListener.AuthenticationFailRecord;
import com.goldgov.kduck.utils.RequestUtils;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class AuthenticationFailureStrategyFilter extends GenericFilterBean {

    public static final String FORM_USERNAME_KEY = "username";
    public static final String OAUTH2_USERNAME_KEY = "client_id";

    private ObjectMapper om = new ObjectMapper();

    private String usernameParameter = FORM_USERNAME_KEY;

    private final List<AuthenticationFailureStrategyHandler> failureStrategyHandlerList;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    private RequestMatcher requestMatcher;

    public AuthenticationFailureStrategyFilter(List<AuthenticationFailureStrategyHandler> failureStrategyHandlerList){
        this.failureStrategyHandlerList = failureStrategyHandlerList;
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher("/oauth/token"),
                new AntPathRequestMatcher("/login", "POST")
        );
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        try{
            attemptAuthentication(request, response);

            chain.doFilter(request, response);

        }catch (AuthenticationFailureException e){
            if(RequestUtils.isAjax(request)){
                JsonObject jsonObject = new JsonObject(e.getNotification(),-2,e.getMessage());
                response.setContentType("application/json");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                try {
                    om.writeValue(response.getOutputStream(),jsonObject);
                } catch (IOException ex) {
                    throw new RuntimeException("预认证失败，返回JSON数据时发送IO错误",ex);
                }
            }else{
                try {
//                            redirectStrategy.sendRedirect(request,response,"/login");
                    failureHandler.setDefaultFailureUrl("/login?error="+e.getNotification());
                    failureHandler.onAuthenticationFailure(request,response,e);
                } catch (Exception ex) {
                    throw new RuntimeException("预认证失败，跳转到登录页时发生错误",ex);
                }
            }
        }

    }

    protected boolean requiresAuthentication(HttpServletRequest request,
                                             HttpServletResponse response) {
        return requestMatcher.matches(request);
    }

    /**
     * 如果预认证失败需要以PreAuthenticationException或子类异常方式返回
     * @param request
     * @param response
     * @throws AuthenticationFailureException
     */
    public void attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationFailureException {
        String username = obtainUsername(request);
        if (username == null) {
            return;
        }
        username = username.trim();

//        Integer failNum = CacheHelper.getByCacheName(AuthenticationFailListener.AUTHENTICATION_FAIL_CAHCE_NAME, username, Integer.class);
//        failNum = failNum == null ? 0 : failNum;
        AuthenticationFailRecord failRecord = CacheHelper.getByCacheName(AuthenticationFailListener.AUTHENTICATION_FAIL_CAHCE_NAME, username, AuthenticationFailRecord.class);

        PreAuthenticationToken authRequest = new PreAuthenticationToken(username,failRecord);

        setDetails(request, authRequest);

        for (AuthenticationFailureStrategyHandler failureStrategyHandler : failureStrategyHandlerList) {
            if(failureStrategyHandler.supports(authRequest,request)) {
                //如果没有任何预认证问题则无需处理，否则以抛出PreAuthenticationException异常的方式体现预认证错误
                boolean clearFailNum = failureStrategyHandler.authenticate(authRequest,request);
                if(clearFailNum){
                    CacheHelper.evict(AuthenticationFailListener.AUTHENTICATION_FAIL_CAHCE_NAME, username);
                }
            }
        }
    }

    protected void setDetails(HttpServletRequest request,
                              PreAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }

    public static class PreAuthenticationToken extends AbstractAuthenticationToken {

        private static final AuthenticationFailRecord NO_FAIL_RECORD = new AuthenticationFailRecord();

        private final Object principal;
        private final AuthenticationFailRecord failRecord;

        public PreAuthenticationToken(Object principal,AuthenticationFailRecord failRecord){
            super(null);
            this.principal = principal;
            this.failRecord = failRecord;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return principal;
        }

        public AuthenticationFailRecord getFailRecord() {
            if(failRecord == null){
                return NO_FAIL_RECORD;
            }
            return failRecord;
        }
    }

    public interface AuthenticationFailureStrategyHandler {

        boolean supports(PreAuthenticationToken authentication,HttpServletRequest httpRequest);

        boolean authenticate(PreAuthenticationToken authentication,HttpServletRequest httpRequest) throws AuthenticationFailureException;

    }

}
