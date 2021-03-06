package cn.kduck.security.oauth2.configuration;

import cn.kduck.security.KduckSecurityProperties;
import cn.kduck.security.filter.AuthenticationFailureStrategyFilter;
import cn.kduck.security.mfa.oauth2.MfaAuthenticatorService;
import cn.kduck.security.mfa.oauth2.MfaPasswordTokenGranter;
import cn.kduck.security.mfa.oauth2.MfaTokenGranter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableAuthorizationServer
@ConditionalOnClass(EnableAuthorizationServer.class)
@ConditionalOnProperty(prefix="kduck.security.oauth2.authServer",name="enabled",havingValue = "true")
public class OAuthAuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;

    @Autowired
    private KduckSecurityProperties securityProperties;

    @Autowired(required = false)
    private JwtAccessTokenConverter accessTokenConverter;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private DataSource dataSource;

    @Autowired(required = false)
    private TokenEnhancer tokenEnhancer;

    @Autowired
    @Lazy
    private AuthenticationFailureStrategyFilter preAuthenticationFilter;

    @Autowired(required = false)
    private MfaAuthenticatorService mfaService;

    @Autowired
    public OAuthAuthServerConfiguration(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.allowFormAuthenticationForClients();
        security.addTokenEndpointAuthenticationFilter(preAuthenticationFilter);
//        security.checkTokenAccess("permitAll()");

    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //?????????????????????,????????????password??????????????????client??????
//        clients.inMemory().withClient("client_1")
//                .resourceIds(DEMO_RESOURCE_ID)
//                .authorizedGrantTypes("client_credentials", "refresh_token")
//                .scopes("select")
//                .authorities("client")
//                .secret(passwordEncoder.encode("123456"))
//
//                .and().withClient("client_2")
//                .resourceIds(DEMO_RESOURCE_ID)
//                .authorizedGrantTypes("password", "refresh_token")
//                .scopes("select")
//                .authorities("client")
//                .secret(passwordEncoder.encode("123456"));
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

        if(securityProperties.getMfa() != null && securityProperties.getMfa().isEnabled()){
            endpoints.tokenGranter(tokenGranter(endpoints));
        }else{
            //?????????????????????????????????????????????????????????????????????????????????mfa??????????????????tokenGranter(endpoints)??????????????????????????????TokenGranter???
            //?????????????????????????????????????????????????????????mfa??????????????????????????????????????????tokenGranter(endpoints)?????????
            endpoints.tokenStore(tokenStore).authenticationManager(authenticationManager);
        }

        endpoints.tokenStore(tokenStore).userDetailsService(userDetailsService);//?????????????????????????????????userDetailsService???????????????UserDetailsService??????????????????

        //JWT
        if(accessTokenConverter != null){
            if(tokenEnhancer != null){
                TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
                List<TokenEnhancer> enhancers = new ArrayList<>();
                enhancers.add(tokenEnhancer);
                enhancers.add(accessTokenConverter);
                enhancerChain.setTokenEnhancers(enhancers);

                endpoints.tokenEnhancer(enhancerChain);
            }

            endpoints.accessTokenConverter(accessTokenConverter);
        }




//        endpoints.pathMapping("/oauth/confirm_access", "/oauth/confirm_access")
//        endpoints.authorizationCodeServices()
    }


    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        List<TokenGranter> granters = new ArrayList();
        granters.add(endpoints.getTokenGranter());//???????????????TokenGranter????????????????????????????????????????????????????????????????????????????????????????????????????????????authenticationManager?????????
        granters.add(new MfaPasswordTokenGranter(endpoints, authenticationManager));
        granters.add(new MfaTokenGranter(endpoints, authenticationManager, mfaService));
        return new CompositeTokenGranter(granters);
    }

}
