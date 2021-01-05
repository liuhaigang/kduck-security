package cn.kduck.security.mfa.exception;

public class MissingTokenException extends MfaException{

    public MissingTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    public MissingTokenException(String msg) {
        super(msg);
    }
}
