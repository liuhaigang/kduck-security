package com.goldgov.kduck.security.exception;

import org.springframework.security.core.AuthenticationException;

public class PreAuthenticationException extends AuthenticationException {

    private final Object notification;

    public PreAuthenticationException(Object notification, String msg) {
        super(msg);
        this.notification = notification;
    }

    public PreAuthenticationException(Object notification) {
        super("预认证失败");
        this.notification = notification;
    }

    public Object getNotification() {
        return notification;
    }
}
