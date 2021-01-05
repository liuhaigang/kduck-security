package cn.kduck.security.mfa.exception;

public class MfaValidationException extends MfaException{

    private final String username;

    public MfaValidationException(String username,String msg, Throwable t) {
        super(msg, t);
        this.username = username;
    }

    public MfaValidationException(String username,String msg) {
        super(msg);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
