package com.goldgov.kduck.security;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.KduckSecurityProperties.Provider;
import com.goldgov.kduck.security.oauth2.web.UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class AuthenticatedUserFilter extends GenericFilterBean {

//    //对于客户端根本不会有这个转换器，更不会去直连认证服务器的表去查询用户
//    @Autowired
//    private TokenTranslator tokenTranslator;
//
//    //对于客户端是没有TokenStore的
//    @Autowired
//    private TokenStore tokenStore;

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String accessToken = extractToken(httpRequest);
        if(accessToken != null){
            //TODO 先判断缓存有没有
            //TODO 根据token调用认证服务的user_info接口得到认证用户并缓存，如果得到返回错误信息，比如token过期或无效，需要同时清除对应缓存
            //TODO 如果没配置客户端user_info链接，默认执行本地请求或使用TokenStore？
            //TODO 创建登录成功事件，设置登录时间、IP以及清除登录失败记录

            if(securityProperties.getOauth2() != null &&
                    securityProperties.getOauth2().getClient() != null &&
                    securityProperties.getOauth2().getClient().getProvider() != null){
//                throw new IllegalArgumentException("Oauth2调用获取用户接口失败，缺少kduck.security.oauth2.client.provider.userInfoUri配置");
                Provider provider = securityProperties.getOauth2().getClient().getProvider();

                URI uri;
                try {
                    uri = new URI(provider.getUserInfoUri());
                } catch (URISyntaxException e) {
                    throw new ServletException("user_info的链接格式不合法：" + provider.getUserInfoUri(),e);
                }

                if(!httpRequest.getRequestURI().equals(uri.getPath())){

                    ResponseEntity<UserInfo> authUserEntity;
                     String userInfoUrl = provider.getUserInfoUri() + "?" + OAuth2AccessToken.ACCESS_TOKEN + "=" + accessToken;
                    try{
                        authUserEntity = restTemplate.getForEntity(userInfoUrl, UserInfo.class);
                    }catch(HttpClientErrorException e){
                        throw new ServletException("调用用户信息接口返回客户端错误（4xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl,e);
                    }catch(HttpServerErrorException e){
                        throw new ServletException("调用用户信息接口返回服务端错误（5xx）：CODE=" + e.getRawStatusCode() + "，URL=" + userInfoUrl,e);
                    }

                    UserInfo userInfo = authUserEntity.getBody();
                    if(userInfo != null){
                        List<String> authorities = userInfo.getAuthorities();
                        List<GrantedAuthority> authoritiesSet = new ArrayList<>(authorities.size());
                        if(authorities != null){
                            for (String authority : authorities) {
                                authoritiesSet.add(new SimpleGrantedAuthority(authority));
                            }
                        }
                        AuthUser authUser = new AuthUser(userInfo.getUserId(),userInfo.getUsername(),"",authoritiesSet);
                        authUser.eraseCredentials();
                        AuthUserHolder.setAuthUser(authUser);
                        CacheHelper.put(accessToken,authUser,3600);
                    }
                }

            }
        }else{
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if(authentication instanceof UsernamePasswordAuthenticationToken){
                Object principal = authentication.getPrincipal();
                if(principal instanceof AuthUser){
                    AuthUserHolder.setAuthUser((AuthUser)principal);
                }
//                    else{
//                        throw new IllegalArgumentException("无法识别的认证对象：" + principal);
//                    }
            }

        }

        try{
            chain.doFilter(request,response);
        }finally {
            AuthUserHolder.reset();
        }

    }

    @Override
    public void destroy() {

    }

    protected String extractToken(HttpServletRequest request) {
        String token = extractHeaderToken(request);
        if (token == null) {
            token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
        }
        return token;
    }

    protected String extractHeaderToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders("Authorization");
        while (headers.hasMoreElements()) {
            String value = headers.nextElement();
            if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
                String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
                int commaIndex = authHeaderValue.indexOf(',');
                if (commaIndex > 0) {
                    authHeaderValue = authHeaderValue.substring(0, commaIndex);
                }
                return authHeaderValue;
            }
        }

        return null;
    }

}
