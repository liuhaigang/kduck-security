package com.goldgov.kduck.security.oauth2.configuration;

import com.goldgov.kduck.security.KduckSecurityProperties;
import com.goldgov.kduck.security.RoleAccessVoter;
import com.goldgov.kduck.security.oauth2.matcher.OAuthRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableResourceServer
@ConditionalOnClass(EnableResourceServer.class)
@ConditionalOnProperty(prefix="kduck.security.oauth2.registration",name="clientId")
public class OauthResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final String RESOURCE_ID = "kduck-oauth2-resource";

    @Autowired
    private RoleAccessVoter roleAccessVoter;

    @Autowired
    private KduckSecurityProperties securityProperties;
    //JWT
    @Autowired
    private TokenStore tokenStore;

//    @Autowired
//    private FrameworkEndpointHandlerMapping endpointHandlerMapping;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId(RESOURCE_ID).stateless(true);

        //JWT
        if(tokenStore instanceof JwtTokenStore){
            DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenStore(tokenStore);
            resources.tokenServices(defaultTokenServices);
        }

    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        List<AccessDecisionVoter<? extends Object>> voterList = new ArrayList();
//        voterList.add(new WebExpressionVoter());
//        voterList.add(new ScopeVoter());
        voterList.add(roleAccessVoter);

        String[] resourcePaths = securityProperties.getRegistration().getResourcePaths();
        List<String> arrayList = new ArrayList(Arrays.asList(resourcePaths));
//        arrayList.add("/role/**");
//        arrayList.add("/user/**");
        http.requestMatcher(new OAuthRequestMatcher(arrayList.toArray(new String[0])));
        // @formatter:off
        http.cors().and()
                .authorizeRequests().accessDecisionManager(new AffirmativeBased(voterList))
                .antMatchers("/oauth/*").permitAll()
                .anyRequest().authenticated()
                .and()
                // Since we want the protected resources to be accessible in the UI as well we need
                // session creation to be allowed (it's disabled by default in 2.0.6)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        // @formatter:on
    }

}
