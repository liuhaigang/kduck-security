package com.goldgov.kduck.security.oauth2.web;

import com.goldgov.kduck.security.UserExtInfo;
import com.goldgov.kduck.security.oauth2.exception.AuthUserNotFoundException;
import com.goldgov.kduck.service.ValueMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
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

    @Autowired
    private TokenStore tokenStore;

    @RequestMapping("/user_info")
    public UserInfo userInfo(Authentication authentication, HttpServletRequest request){
        if(authentication instanceof OAuth2Authentication){

            OAuth2Authentication oauthAuth =  ((OAuth2Authentication)authentication);

            UserInfo userInfo = new UserInfo();

            String accessToken = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);
            if(accessToken != null){
                OAuth2AccessToken oauth2AccessToken = tokenStore.readAccessToken(accessToken);
                userInfo.getDetails().put("expiration",oauth2AccessToken.getExpiration());
                userInfo.getDetails().put("refresh_token",oauth2AccessToken.getRefreshToken().getValue());
            }

            userInfo.setUsername(oauthAuth.getName());
            if(!oauthAuth.isClientOnly()){
                //根据用户登录名查询认证用户并返回
                UserDetails authUser;
                try{
                    authUser = userDetailsService.loadUserByUsername(oauthAuth.getName());
                }catch (UsernameNotFoundException e){
                    throw new AuthUserNotFoundException(oauthAuth.getName(),"用户不存在：" + oauthAuth.getName());
                }

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
