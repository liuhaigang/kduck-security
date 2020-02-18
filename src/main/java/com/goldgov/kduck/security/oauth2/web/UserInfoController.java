package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.security.AuthUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth")
public class UserInfoController {

    @Autowired
    private UserDetailsService userDetailsService;

    @RequestMapping("/user_info")
    public UserInfo userInfo(Authentication authentication){
        if(authentication instanceof OAuth2Authentication){
            OAuth2Authentication oauthAuth =  ((OAuth2Authentication)authentication);

            UserInfo userInfo;
            if(!oauthAuth.isClientOnly()){
                //根据用户登录名查询认证用户并返回
                AuthUser authUser = (AuthUser)userDetailsService.loadUserByUsername(oauthAuth.getName());
                authUser.eraseCredentials();
                userInfo = new UserInfo(authUser);
            }else{
                userInfo = new UserInfo();
                userInfo.setClientOnly(true);
            }

            return userInfo;
        } else {
            throw new RuntimeException("/oauth2/user_info接口仅为OAuth2接口调用");
        }

    }
}
