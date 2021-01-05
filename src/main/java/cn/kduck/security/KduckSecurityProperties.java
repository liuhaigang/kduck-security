package cn.kduck.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;

import java.util.Set;

@ConfigurationProperties(prefix = "kduck.security")
public class KduckSecurityProperties {

    private String loginPage;

    private boolean httpBasic = true;

    private String defaultSuccessUrl;
    private String defaultFailureUrl;

    private String accessDeniedUrl;

    private String successUrlParameter;
    private boolean alwaysUse;
    private boolean forwardToFailureUrl;

    private String[] ignored;

    private MfaConfig mfa;

    private OAuth2Config oauth2;

    public MfaConfig getMfa() {
        return mfa;
    }

    public void setMfa(MfaConfig mfa) {
        this.mfa = mfa;
    }

    public String getAccessDeniedUrl() {
        return accessDeniedUrl;
    }

    public void setAccessDeniedUrl(String accessDeniedUrl) {
        this.accessDeniedUrl = accessDeniedUrl;
    }

    public String[] getIgnored() {
        return ignored;
    }

    public void setIgnored(String[] ignored) {
        this.ignored = ignored;
    }

    public String getSuccessUrlParameter() {
        return successUrlParameter;
    }

    public void setSuccessUrlParameter(String successUrlParameter) {
        this.successUrlParameter = successUrlParameter;
    }

    public boolean isForwardToFailureUrl() {
        return forwardToFailureUrl;
    }

    public void setForwardToFailureUrl(boolean forwardToFailureUrl) {
        this.forwardToFailureUrl = forwardToFailureUrl;
    }

    public String getDefaultFailureUrl() {
        return defaultFailureUrl;
    }

    public void setDefaultFailureUrl(String defaultFailureUrl) {
        this.defaultFailureUrl = defaultFailureUrl;
    }

    public String getDefaultSuccessUrl() {
        return defaultSuccessUrl;
    }

    public void setDefaultSuccessUrl(String defaultSuccessUrl) {
        this.defaultSuccessUrl = defaultSuccessUrl;
    }

    public boolean isAlwaysUse() {
        return alwaysUse;
    }

    public void setAlwaysUse(boolean alwaysUse) {
        this.alwaysUse = alwaysUse;
    }

    public boolean isHttpBasic() {
        return httpBasic;
    }

    public void setHttpBasic(boolean httpBasic) {
        this.httpBasic = httpBasic;
    }

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public OAuth2Config getOauth2() {
        return oauth2;
    }

    public void setOauth2(OAuth2Config oauth2) {
        this.oauth2 = oauth2;
    }

    public static class OAuth2Config {

        public static final String DEFAULT_JWT_KEY = "KDUCK-JWT-SIGNING-KEY";

        private String tokenStore;
        private String jwtKey = DEFAULT_JWT_KEY;

        private AuthServer authServer;
        private ResServer resServer;
        private Client client;

        public String getJwtKey() {
            return jwtKey;
        }

        public void setJwtKey(String jwtKey) {
            this.jwtKey = jwtKey;
        }

        public Client getClient() {
            return client;
        }

        public void setClient(Client client) {
            this.client = client;
        }

        public String getTokenStore() {
            return tokenStore;
        }

        public void setTokenStore(String tokenStore) {
            this.tokenStore = tokenStore;
        }

        public AuthServer getAuthServer() {
            return authServer;
        }

        public void setAuthServer(AuthServer authServer) {
            this.authServer = authServer;
        }

        public ResServer getResServer() {
            return resServer;
        }

        public void setResServer(ResServer resServer) {
            this.resServer = resServer;
        }
    }

    public static class Provider {

        private String hostUri;

        private String authorizationUri = "/oauth/authorize";
        private String tokenUri = "/oauth/token";
        private String userInfoUri = "/oauth/user_info";

        public String getHostUri() {
            if(hostUri.endsWith("/")){
                return hostUri.substring(0,hostUri.length()-1);
            }
            return hostUri;
        }

        public void setHostUri(String hostUri) {
            this.hostUri = hostUri;
        }

        public String getAuthorizationUri() {
            if(StringUtils.hasText(hostUri) && !authorizationUri.startsWith("http")){
                return getHostUri() + authorizationUri;
            }
            return authorizationUri;
        }

        public void setAuthorizationUri(String authorizationUri) {
            this.authorizationUri = authorizationUri;
        }

        public String getTokenUri() {
            if(StringUtils.hasText(hostUri) && !tokenUri.startsWith("http")){
                return getHostUri() + tokenUri;
            }
            return tokenUri;
        }

        public void setTokenUri(String tokenUri) {
            this.tokenUri = tokenUri;
        }

        public String getUserInfoUri() {
            if(StringUtils.hasText(hostUri) && !userInfoUri.startsWith("http")){
                return getHostUri() + userInfoUri;
            }
            return userInfoUri;
        }

        public void setUserInfoUri(String userInfoUri) {
            this.userInfoUri = userInfoUri;
        }
    }


    public static class Registration {

        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private Set<String> scope;
        private String clientName;
        private String authorizationGrantType;

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }

        public Set<String> getScope() {
            return scope;
        }

        public void setScope(Set<String> scope) {
            this.scope = scope;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public String getAuthorizationGrantType() {
            return authorizationGrantType;
        }

        public void setAuthorizationGrantType(String authorizationGrantType) {
            this.authorizationGrantType = authorizationGrantType;
        }

    }


    /**
     * 客户端配置
     */
    public static class Client{

        private Provider provider;
        private Registration registration;

        public Provider getProvider() {
            return provider;
        }

        public void setProvider(Provider provider) {
            this.provider = provider;
        }

        public Registration getRegistration() {
            return registration;
        }

        public void setRegistration(Registration registration) {
            this.registration = registration;
        }
    }

    /**
     * 资源服务器配置
     */
    public static class ResServer{
        private String[] resourcePaths;

        private boolean enabled;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String[] getResourcePaths() {
            return resourcePaths;
        }

        public void setResourcePaths(String[] resourcePaths) {
            this.resourcePaths = resourcePaths;
        }
    }

    /**
     * 认证服务器配置
     */
    public static class AuthServer{
        private boolean enabled;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * 多因素认证配置
     */
    public static class MfaConfig {
        private boolean enabled;
        private String validateUrl;
        private String mfaPage;
        private String type;//TOTP，CODE
        private String sendStrategy;//mail,sms

        private String[] mfaUsers;

        public String[] getMfaUsers() {
            return mfaUsers;
        }

        public void setMfaUsers(String[] mfaUsers) {
            this.mfaUsers = mfaUsers;
        }

        public String getSendStrategy() {
            return sendStrategy;
        }

        public void setSendStrategy(String sendStrategy) {
            this.sendStrategy = sendStrategy;
        }

        public String getValidateUrl() {
            return validateUrl;
        }

        public void setValidateUrl(String validateUrl) {
            this.validateUrl = validateUrl;
        }

        public String getMfaPage() {
            return mfaPage;
        }

        public void setMfaPage(String mfaPage) {
            this.mfaPage = mfaPage;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }

}
