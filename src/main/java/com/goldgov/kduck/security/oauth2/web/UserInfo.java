package com.goldgov.kduck.security.oauth2.web;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserInfo {

    private String userId;
    private String username;
    private List<String> authorities = Collections.emptyList();
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;

    private boolean clientOnly = false;

    private Map details = new HashMap();

    public UserInfo(){}

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isClientOnly() {
        return clientOnly;
    }

    public void setClientOnly(boolean clientOnly) {
        this.clientOnly = clientOnly;
    }

    public Map getDetails() {
        return details;
    }

    public void setDetails(Map details) {
        this.details = details;
    }
}
