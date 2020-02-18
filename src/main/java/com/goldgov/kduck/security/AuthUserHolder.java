package com.goldgov.kduck.security;

public final class AuthUserHolder {

    private static ThreadLocal<AuthUser> authUserThreadLocal = new ThreadLocal<>();

    private AuthUserHolder(){}

    static void setAuthUser(AuthUser authUser){
        authUserThreadLocal.set(authUser);
    }

    public static AuthUser getAuthUser() {
        return authUserThreadLocal.get();
    }

    static void reset(){
        authUserThreadLocal.remove();
    }
}
