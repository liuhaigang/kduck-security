package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.security.KduckSecurityProperties;
import com.goldgov.kduck.security.KduckSecurityProperties.Client;
import com.goldgov.kduck.security.KduckSecurityProperties.Provider;
import com.goldgov.kduck.security.KduckSecurityProperties.Registration;
import com.goldgov.kduck.web.json.JsonObject;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@Api(tags = "oauth相关")
public class LoginController {

//    @Autowired(required = false)
//    private TokenEndpoint tokenEndpoint;

    @Autowired
    private KduckSecurityProperties securityProperties;

    private OAuth2RestTemplate restTemplate;

    @RequestMapping("/login")
    @ApiOperation("oauth回调登录")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "code", value = "授权码", paramType = "query")
    })
    public JsonObject login(String code){
        Client client = securityProperties.getClient();
        Provider provider = client.getProvider();
        Registration registration = client.getRegistration();
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

        restTemplate = new OAuth2RestTemplate(resourceDetails,oAuth2ClientContext);
        OAuth2AccessToken accessToken = restTemplate.getAccessToken();

        return new JsonObject(accessToken);
    }

//    @RequestMapping("/login")
//    @ApiOperation("oauth回调登录")
//    @ApiImplicitParams({
//            @ApiImplicitParam(name = "userName", value = "姓名", paramType = "query"),
//            @ApiImplicitParam(name = "password", value = "密码", paramType = "query"),
//    })
//    public JsonObject login(String userName, String password){
//        Map<String, String> postParameters = new HashMap<>();
//        postParameters.put("username", userName);
//        postParameters.put("password", password);
//        postParameters.put("client_id", "client_id");
//        postParameters.put("client_secret", "123456");
//        postParameters.put("grant_type", "password");
//        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("client_id", "123456", Collections.emptyList());
//        try {
//            ResponseEntity<OAuth2AccessToken> responseEntity = tokenEndpoint.postAccessToken(auth, postParameters);
//            return new JsonObject(responseEntity);
//        } catch (HttpRequestMethodNotSupportedException e) {
//            e.printStackTrace();
//        }
//        return JsonObject.FAIL;
//    }
}
