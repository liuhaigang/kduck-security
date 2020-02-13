package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.web.json.JsonObject;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@Api(tags = "oauth相关")
public class LoginController {

    @Autowired(required = false)
    private TokenEndpoint tokenEndpoint;

    @RequestMapping("/login")
    @ApiOperation("oauth回调登录")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "code", value = "授权码", paramType = "query")
    })
    public JsonObject login(String code){
        Map<String, String> postParameters = new HashMap<>();
//        postParameters.put("username", userName);
//        postParameters.put("password", password);
        postParameters.put("client_id", "client_id");
        postParameters.put("client_secret", "123456");
        postParameters.put("grant_type", "password");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken("client_id", "123456", Collections.emptyList());
        try {
            ResponseEntity<OAuth2AccessToken> responseEntity = tokenEndpoint.postAccessToken(auth, postParameters);
            return new JsonObject(responseEntity);
        } catch (HttpRequestMethodNotSupportedException e) {
            e.printStackTrace();
        }
        return JsonObject.FAIL;
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
