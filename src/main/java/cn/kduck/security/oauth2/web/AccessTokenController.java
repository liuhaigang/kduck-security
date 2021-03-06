package cn.kduck.security.oauth2.web;

import cn.kduck.security.KduckSecurityProperties;
import cn.kduck.security.KduckSecurityProperties.Client;
import cn.kduck.security.KduckSecurityProperties.OAuth2Config;
import cn.kduck.security.KduckSecurityProperties.Provider;
import cn.kduck.security.KduckSecurityProperties.Registration;
import cn.kduck.security.handler.OAuthTokenSuccessHandler;
import cn.kduck.core.web.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@RestController
@RequestMapping("/oauth")
public class AccessTokenController {

//    @Autowired(required = false)
//    private TokenEndpoint tokenEndpoint;

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Autowired(required = false)
    private OAuthTokenSuccessHandler successHandler;


    /**
     * OAuth客户端认证成功后回调请求，用于获取AccessToken
     * @param code 授权码
     * @return AccessToken信息
     */
    @RequestMapping("/token/code")
    public JsonObject login(String code){
        Registration registration = getRegistration();
        Provider provider = getProvider();

        AuthorizationCodeResourceDetails resourceDetails = new AuthorizationCodeResourceDetails();
        resourceDetails.setUserAuthorizationUri(provider.getAuthorizationUri());
        resourceDetails.setAccessTokenUri(provider.getTokenUri());
        resourceDetails.setScope(new ArrayList<>(registration.getScope()));
        resourceDetails.setClientId(registration.getClientId());
        resourceDetails.setClientSecret(registration.getClientSecret());

        DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
        accessTokenRequest.setAuthorizationCode(code);
        accessTokenRequest.setPreservedState(registration.getRedirectUri());
        OAuth2ClientContext oAuth2ClientContext = new DefaultOAuth2ClientContext(accessTokenRequest);

        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails,oAuth2ClientContext);
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();

        successHandler(accessToken);

        return new JsonObject(accessToken);
    }

    /**
     * 向认证服务器发起获取AccessToken的请求（password模式）
     * @param userName 用户名
     * @param password 密码
     * @return AccessToken信息
     */
    @PostMapping("/token/password")
//    @ApiOperation("oauth2的password认证类型方式登录")
//    @ApiImplicitParams({
//            @ApiImplicitParam(name = "userName", value = "姓名", paramType = "query"),
//            @ApiImplicitParam(name = "password", value = "密码", paramType = "query"),
//    })
    public JsonObject login(String userName, String password, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {

        Registration registration = getRegistration();
        Provider provider = getProvider();

        ResourceOwnerPasswordResourceDetails resourceDetails = new ResourceOwnerPasswordResourceDetails();
        resourceDetails.setUsername(userName);
        resourceDetails.setPassword(password);
        resourceDetails.setClientId(registration.getClientId());
        resourceDetails.setClientSecret(registration.getClientSecret());

        resourceDetails.setAccessTokenUri(provider.getTokenUri());

        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails);
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();

//        AuthUser authUser = AuthUserHolder.getAuthUser();
//        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(authUser.getUsername(),null,authUser.getAuthorities());
//        successHandler.onAuthenticationSuccess(request,response,authentication);

        successHandler(accessToken);

        return new JsonObject(accessToken);
    }

    /**
     * 向认证服务器发起获取AccessToken的请求（client模式）
     * @return AccessToken信息
     */
    @PostMapping("/token/client")
//    @ApiOperation("oauth2的client认证类型方式登录")
    public JsonObject login(){
        Registration registration = getRegistration();
        Provider provider = getProvider();

        ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
        resourceDetails.setClientId(registration.getClientId());
        resourceDetails.setClientSecret(registration.getClientSecret());
        resourceDetails.setAccessTokenUri(provider.getTokenUri());

        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails);
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();

        successHandler(accessToken);

        return new JsonObject(accessToken);
    }

    private void successHandler(OAuth2AccessToken accessToken) {
        if(successHandler != null){
            successHandler.onTokenSuccess(accessToken);
        }
    }

    private Provider getProvider(){
        Provider provider = getClient().getProvider();
        Assert.notNull(provider,"没有配置认证服务器信息，请完善配置项：kduck.security.oauth2.client.provider相关配置项");
        return provider;
    }

    private Registration getRegistration(){
        Registration registration = getClient().getRegistration();
        Assert.notNull(registration,"没有配置客户端注册信息，请完善配置项：kduck.security.oauth2.client.registration相关配置项");
        return registration;
    }

    private Client getClient(){
        OAuth2Config oauth2Config = securityProperties.getOauth2();
        Client client = null;
        if(oauth2Config != null){
            client = oauth2Config.getClient();
        }
        Assert.notNull(client,"没有配置OAuth客户端信息，请完善配置项：kduck.security.oauth2.client下的provider和registration相关配置项");

        return client;
    }
}
