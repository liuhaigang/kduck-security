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
        //配置两个客户端,一个用于password认证一个用于client认证
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
            //下面一行此处仅用于判定是否启用密码授权模式，如果启用了mfa，为了下面的tokenGranter(endpoints)方法不注入密码模式的TokenGranter。
            //将其注释，不会影响原有逻辑，如果不启用mfa才让其生效，且无需执行下面的tokenGranter(endpoints)方法。
            endpoints.tokenStore(tokenStore).authenticationManager(authenticationManager);
        }

        endpoints.tokenStore(tokenStore).userDetailsService(userDetailsService);//刷新接口必须显示的指定userDetailsService，否则会抛UserDetailsService必须但未定义

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
        granters.add(endpoints.getTokenGranter());//获取默认的TokenGranter，但由于密码模式是自定义的，因此不能将密码模式默认构建，需要将上面的指定authenticationManager注释掉
        granters.add(new MfaPasswordTokenGranter(endpoints, authenticationManager));
        granters.add(new MfaTokenGranter(endpoints, authenticationManager, mfaService));
        return new CompositeTokenGranter(granters);
    }

}
