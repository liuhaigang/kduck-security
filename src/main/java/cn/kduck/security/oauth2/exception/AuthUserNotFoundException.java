package cn.kduck.security.oauth2.exception;

public class AuthUserNotFoundException extends RuntimeException{

    private String username;

    public AuthUserNotFoundException(String username) {
        this.username = username;
    }

    public AuthUserNotFoundException(String username,String message) {
        super(message);
        this.username = username;
    }

    public AuthUserNotFoundException(String username,String message, Throwable cause) {
        super(message, cause);
        this.username = username;
    }

    public AuthUserNotFoundException(Throwable cause) {
        super(cause);
    }

    public String getUsername() {
        return username;
    }
}
