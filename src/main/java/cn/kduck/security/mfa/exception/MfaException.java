package cn.kduck.security.mfa.exception;

import org.springframework.security.core.AuthenticationException;

public class MfaException extends AuthenticationException {

    public MfaException(String msg, Throwable t) {
        super(msg, t);
    }

    public MfaException(String msg) {
        super(msg);
    }
}
