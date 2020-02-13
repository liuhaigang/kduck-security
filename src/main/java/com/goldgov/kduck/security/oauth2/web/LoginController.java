package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.security.KduckSecurityProperties;
import com.goldgov.kduck.security.KduckSecurityProperties.Client;
import com.goldgov.kduck.security.KduckSecurityProperties.Provider;
import com.goldgov.kduck.security.KduckSecurityProperties.Registration;
import com.goldgov.kduck.web.json.JsonObject;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
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

import java.util.ArrayList;

@RestController
@RequestMapping("/oauth")
public class LoginController {

//    @Autowired(required = false)
//    private TokenEndpoint tokenEndpoint;

    @Autowired
    private KduckSecurityProperties securityProperties;

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

        return new JsonObject(accessToken);
    }

    /**
     * 向认证服务器发起获取AccessToken的请求（password模式）
     * @param userName 用户名
     * @param password 密码
     * @return AccessToken信息
     */
    @PostMapping("/token/password")
    @ApiOperation("oauth2的password认证类型方式登录")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "userName", value = "姓名", paramType = "query"),
            @ApiImplicitParam(name = "password", value = "密码", paramType = "query"),
    })
    public JsonObject login(String userName, String password){

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

        return new JsonObject(accessToken);
    }

    /**
     * 向认证服务器发起获取AccessToken的请求（client模式）
     * @return AccessToken信息
     */
    @PostMapping("/token/client")
    @ApiOperation("oauth2的client认证类型方式登录")
    public JsonObject login(){
        Registration registration = getRegistration();
        Provider provider = getProvider();

        ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
        resourceDetails.setClientId(registration.getClientId());
        resourceDetails.setClientSecret(registration.getClientSecret());
        resourceDetails.setAccessTokenUri(provider.getTokenUri());

        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resourceDetails);
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();

        return new JsonObject(accessToken);
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
        Client client = securityProperties.getClient();
        Assert.notNull(client,"没有配置OAuth客户端信息，请完善配置项：kduck.security.oauth2.client下的provider和registration相关配置项");

        return client;
    }
}
