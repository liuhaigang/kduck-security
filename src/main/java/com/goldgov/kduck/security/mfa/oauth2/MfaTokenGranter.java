package com.goldgov.kduck.security.mfa.oauth2;

import com.goldgov.kduck.security.mfa.MfaTokenService;
import com.goldgov.kduck.security.mfa.MfaUserDetails;
import com.goldgov.kduck.security.mfa.MfaUserDetailsService;
import com.goldgov.kduck.utils.SpringBeanUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class MfaTokenGranter extends AbstractTokenGranter {
    private static final String GRANT_TYPE = "mfa";

    private final TokenStore tokenStore;
    private final ClientDetailsService clientDetailsService;
    private final AuthenticationManager authenticationManager;
//    private final MfaAuthenticatorService mfaService;

    private MfaTokenService mfaTokenService;
    private MfaUserDetailsService mfaUserDetailsService;

    public MfaTokenGranter(AuthorizationServerEndpointsConfigurer endpointsConfigurer, AuthenticationManager authenticationManager, MfaAuthenticatorService mfaService) {
        super(endpointsConfigurer.getTokenServices(), endpointsConfigurer.getClientDetailsService(), endpointsConfigurer.getOAuth2RequestFactory(), GRANT_TYPE);
        this.tokenStore = endpointsConfigurer.getTokenStore();
        this.clientDetailsService = endpointsConfigurer.getClientDetailsService();
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        final String mfaToken = parameters.get("mfa_token");
        if (mfaToken != null) {
            OAuth2Authentication authentication = loadAuthentication(mfaToken);
            final String username = authentication.getName();
            if (parameters.containsKey("mfa_code")) {
                String mfaCode = parameters.get("mfa_code");

                if(mfaTokenService == null){
                    mfaTokenService = SpringBeanUtils.getBean(MfaTokenService.class);
                }
                if(mfaUserDetailsService == null){
                    mfaUserDetailsService = SpringBeanUtils.getBean(MfaUserDetailsService.class);
                }

                MfaUserDetails mfaUserDetails = mfaUserDetailsService.loadUserByUsername(username);
                if (mfaTokenService.isTokenValid(mfaUserDetails, mfaCode)) {
//                if (mfaService.verifyCode(username, code)) {
                    return getAuthentication(tokenRequest, authentication);
                }
            } else {
                throw new InvalidRequestException("Missing MFA code");
            }
            throw new InvalidGrantException("Invalid MFA code");
        } else {
            throw new InvalidRequestException("Missing MFA token");
        }
    }

    private OAuth2Authentication loadAuthentication(String accessTokenValue) {
        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        } else if (accessToken.isExpired()) {
            this.tokenStore.removeAccessToken(accessToken);
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        } else {
            OAuth2Authentication result = this.tokenStore.readAuthentication(accessToken);
            if (result == null) {
                throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
            }
            return result;
        }
    }

    private OAuth2Authentication getAuthentication(TokenRequest tokenRequest, OAuth2Authentication authentication) {
        Authentication user = authenticationManager.authenticate(authentication.getUserAuthentication());
        Object details = authentication.getDetails();
        authentication = new OAuth2Authentication(authentication.getOAuth2Request(), user);
        authentication.setDetails(details);

        String clientId = authentication.getOAuth2Request().getClientId();
        if (clientId != null && clientId.equals(tokenRequest.getClientId())) {
            if (this.clientDetailsService != null) {
                try {
                    this.clientDetailsService.loadClientByClientId(clientId);
                } catch (ClientRegistrationException e) {
                    throw new InvalidTokenException("Client not valid: " + clientId, e);
                }
            }
            return refreshAuthentication(authentication, tokenRequest);
        } else {
            throw new InvalidGrantException("Client is missing or does not correspond to the MFA token");
        }
    }

    private OAuth2Authentication refreshAuthentication(OAuth2Authentication authentication, TokenRequest request) {
        Set<String> scope = request.getScope();
        OAuth2Request clientAuth = authentication.getOAuth2Request().refresh(request);
        if (scope != null && !scope.isEmpty()) {
            Set<String> originalScope = clientAuth.getScope();
            if (originalScope == null || !originalScope.containsAll(scope)) {
                throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope + ".", originalScope);
            }

            clientAuth = clientAuth.narrowScope(scope);
        }
        return new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
    }
}
