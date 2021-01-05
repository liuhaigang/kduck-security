package cn.kduck.security.mfa.exception;

public class IllegalTokenException extends MfaException{

    public IllegalTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    public IllegalTokenException(String msg) {
        super(msg);
    }
}
