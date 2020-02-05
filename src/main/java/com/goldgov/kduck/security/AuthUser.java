package com.goldgov.kduck.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Date;

/**
 * LiuHG
 */
public class AuthUser extends User {

    private final String userId;
    private final Date loginDate;
    private String loginIp;

    public AuthUser(String userId,String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.userId = userId;
        loginDate = new Date();
    }

    public AuthUser(String userId,String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.userId = userId;
        loginDate = new Date();
    }

    public String getUserId() {
        return userId;
    }

    public Date getLoginDate() {
        return loginDate;
    }

    public String getLoginIp() {
        return loginIp;
    }

    public void setLoginIp(String loginIp) {
        if(this.loginIp != null){
            return;
        }
        this.loginIp = loginIp;
    }
}
