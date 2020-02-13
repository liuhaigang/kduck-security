package com.goldgov.kduck.security.oauth2.configuration;

import com.goldgov.kduck.security.KduckSecurityProperties;
import com.goldgov.kduck.security.KduckSecurityProperties.Client;
import com.goldgov.kduck.security.KduckSecurityProperties.Provider;
import com.goldgov.kduck.security.KduckSecurityProperties.Registration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.util.Assert;

import java.util.ArrayList;

@Configuration
public class OAuthClientConfiguration {

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Bean
    public AuthorizationCodeResourceDetails authorizationCodeResourceDetails(){
        Client client = securityProperties.getClient();

        Assert.notNull(client,"没有配置OAuth客户端信息，请完善配置项：kduck.security.oauth2.client下的provider和registration相关配置项");

        Provider provider = client.getProvider();
        Registration registration = client.getRegistration();

        Assert.notNull(provider,"没有配置认证服务器信息，请完善配置项：kduck.security.oauth2.client.provider相关配置项");
        Assert.notNull(registration,"没有配置客户端注册信息，请完善配置项：kduck.security.oauth2.client.registration相关配置项");

        AuthorizationCodeResourceDetails resourceDetails = new AuthorizationCodeResourceDetails();
        resourceDetails.setUserAuthorizationUri(provider.getAuthorizationUri());
        resourceDetails.setAccessTokenUri(provider.getTokenUri());
        resourceDetails.setScope(new ArrayList<>(registration.getScope()));
        resourceDetails.setClientId(registration.getClientId());
        resourceDetails.setClientSecret(registration.getClientSecret());

        return resourceDetails;
    }
}
