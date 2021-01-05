package cn.kduck.security.mfa;

public interface MfaTokenService {

    void addToken(String username, String token);

    boolean isTokenValid(MfaUserDetails mfaUserDetails, String token);

    String generateToken();
}
