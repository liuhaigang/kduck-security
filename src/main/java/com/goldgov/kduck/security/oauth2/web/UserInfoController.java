package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.security.UserExtInfo;
import com.goldgov.kduck.service.ValueMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RestController
@RequestMapping("/oauth")
public class UserInfoController {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired(required = false)
    private UserExtInfo userExtInfo;

    @RequestMapping("/user_info")
    public UserInfo userInfo(Authentication authentication){
        if(authentication instanceof OAuth2Authentication){
            OAuth2Authentication oauthAuth =  ((OAuth2Authentication)authentication);

            UserInfo userInfo = new UserInfo();
            userInfo.setUsername(oauthAuth.getName());
            if(!oauthAuth.isClientOnly()){
                //根据用户登录名查询认证用户并返回
                UserDetails authUser = userDetailsService.loadUserByUsername(oauthAuth.getName());

                userInfo.setAccountNonExpired(authUser.isAccountNonExpired());
                userInfo.setAccountNonLocked(authUser.isAccountNonLocked());
                userInfo.setEnabled(authUser.isEnabled());

                Collection<? extends GrantedAuthority> authorities = authUser.getAuthorities();
                List<String> roleList = new ArrayList<>(authorities.size());
                for (GrantedAuthority authority : authorities) {
                    roleList.add(authority.getAuthority());
                }
                userInfo.setAuthorities(roleList);

                if(userExtInfo != null){
                    ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(oauthAuth.getName());
                    if(userExtInfo == null){
                        throw new RuntimeException("获取用户的扩展信息不能为null: " + oauthAuth.getName());
                    }
                    userInfo.setDetails(userExtInfo);
                }
            }else{
                userInfo.setClientOnly(true);
            }

            return userInfo;
        } else {
            throw new RuntimeException("/oauth2/user_info接口仅为OAuth2接口调用");
        }

    }
}
