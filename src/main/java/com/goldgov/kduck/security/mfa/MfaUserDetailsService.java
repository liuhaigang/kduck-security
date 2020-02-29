package com.goldgov.kduck.security.mfa;

/**
 * 多因素认证用户业务接口，获取的认证用户中包含常用的用户信息，如手机号、邮箱及用于TOTP的密钥
 * @author LiuHG
 */
public interface MfaUserDetailsService {

    /**
     * 根据用户名判断指定用户是否需要进行多因素认证
     * @param username 用户登录名
     * @return true需要进行多因素认证，false不需要进行多因素认证
     */
    boolean isEnabled(String username);

    /**
     * 根据用户名查询多因素认证用户明细对象
     * @param username 用户登录名
     * @return 返回MFA用户明细对象，如果返回null则表示指定用户不需要进行多因素认证
     */
    MfaUserDetails loadUserByUsername(String username);

}
