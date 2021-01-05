package cn.kduck.security.mfa.oauth2;


public class MfaAuthenticatorService {

//    private final MfaUserDetailsService mfaUserDetailsService;
//
//    public MfaAuthenticatorService(MfaUserDetailsService mfaUserDetailsService){
//        this.mfaUserDetailsService = mfaUserDetailsService;
//    }
//
//    private GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();
//
//    public boolean isEnabled(String username) {
//        return mfaUserDetailsService.isEnabled(username);
//    }
//
//    public boolean verifyCode(String username, int code) {
//        MfaUserDetails mfaUserDetails = mfaUserDetailsService.loadUserByUsername(username);
//        if(mfaUserDetails == null){
//            throw new RuntimeException("mfaUserDetails == null,username:"+username);
//        }
//        return code == googleAuthenticator.getTotpPassword(mfaUserDetails.getSecret());
//    }
}
