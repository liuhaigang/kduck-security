package cn.kduck.security.oauth2.web;

import cn.kduck.security.UserExtInfo;
import cn.kduck.security.oauth2.exception.AuthUserNotFoundException;
import cn.kduck.core.service.ValueMap;
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
                //????????????????????????????????????????????????
                UserDetails authUser;
                try{
                    authUser = userDetailsService.loadUserByUsername(oauthAuth.getName());
                }catch (UsernameNotFoundException e){
                    throw new AuthUserNotFoundException(oauthAuth.getName(),"??????????????????" + oauthAuth.getName());
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
                        throw new RuntimeException("????????????????????????????????????null: " + oauthAuth.getName());
                    }
                    userInfo.setDetails(userExtInfo);
                }
            }else{
                userInfo.setClientOnly(true);
            }

            return userInfo;
        } else {
            throw new RuntimeException("/oauth2/user_info????????????OAuth2????????????");
        }

    }
}
