package cn.kduck.security.mfa;

import cn.kduck.security.configuration.WebSecurityConfiguration.IgnoringRequestMatcher;
import cn.kduck.security.mfa.exception.IllegalTokenException;
import cn.kduck.security.mfa.exception.MfaValidationException;
import cn.kduck.security.mfa.exception.MissingTokenException;
import cn.kduck.security.handler.LoginFailHandler;
import cn.kduck.security.handler.LoginSuccessHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MfaAuthenticationValidationFilter extends OncePerRequestFilter {

    public static final String DEFAULT_MFA_PARAMETER_NAME = "mfa_token";
    public String mfaParameterName = DEFAULT_MFA_PARAMETER_NAME;
    private final MfaUserDetailsService mfaUserDetailsService;
    private MfaTokenService tokenService;
    private String endpoint;
    private final RequestMatcher ignoringRequestMatcher;

    private LoginSuccessHandler successHandler = new LoginSuccessHandler();
    private LoginFailHandler failureHandler = new LoginFailHandler();

    public MfaAuthenticationValidationFilter(MfaUserDetailsService mfaUserDetailsService, MfaTokenService tokenService, String endpoint, String successUrl, String mfaAuthUrl, RequestMatcher ignoringRequestMatcher) {
        this.mfaUserDetailsService = mfaUserDetailsService;
        this.tokenService = tokenService;
        this.endpoint = endpoint;
        this.ignoringRequestMatcher = ignoringRequestMatcher;
        if(successUrl != null){
            successHandler.setDefaultTargetUrl(successUrl);
        }

        if(mfaAuthUrl != null){
            failureHandler.setDefaultFailureUrl(mfaAuthUrl);
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
//        HttpServletRequest req = (HttpServletRequest) request;
//        HttpServletResponse resp = (HttpServletResponse) response;
        if(ignoringRequestMatcher.matches(request)){
            filterChain.doFilter(request,response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Make sure validation endpoint was requested before continuing
        String path = request.getRequestURI().substring(request.getContextPath().length());
        if (!path.equals(endpoint)) {
            if(auth == null || !(auth instanceof MfaAuthenticationToken)){
                filterChain.doFilter(request, response);
                return;
            }else if(auth instanceof MfaAuthenticationToken){
                failureHandler.onAuthenticationFailure(request,response,new MfaValidationException(auth.getName(),"??????FMA??????"));
                return;
            }
        }

        // Get token from request
        String token = request.getParameter(mfaParameterName);
        if (token == null) {
            throw new MissingTokenException("MFA???????????????????????????" + mfaParameterName);
        }

        // Get username from security context
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth == null) {
//            resp.sendRedirect(mfaAuthUrl);
//            return;
//        }
        if (!(auth instanceof MfaAuthenticationToken)) {
            throw new IllegalTokenException("MFA??????Token???????????????:" + auth.getClass().getName());
        }

        MfaAuthenticationToken authToken = (MfaAuthenticationToken) auth;
        String username = authToken.getName();

        // Validate token
        MfaUserDetails mfaUserDetails = mfaUserDetailsService.loadUserByUsername(username);
        if (tokenService.isTokenValid(mfaUserDetails, token)) {
            SecurityContextHolder.getContext().setAuthentication(authToken.getEmbeddedToken());
            successHandler.onAuthenticationSuccess(request,response,authToken.getEmbeddedToken());
        } else {
//            SecurityContextHolder.getContext().setAuthentication(null);
            failureHandler.onAuthenticationFailure(request,response,new MfaValidationException(username,"MFA????????????"));
        }
    }
}