package cn.kduck.security.oauth2.configuration;

import cn.kduck.security.KduckSecurityProperties;
import cn.kduck.security.KduckSecurityProperties.ResServer;
import cn.kduck.security.RoleAccessVoter;
import cn.kduck.security.oauth2.matcher.OAuthRequestMatcher;
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
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
@EnableResourceServer
@ConditionalOnClass(EnableResourceServer.class)
@ConditionalOnProperty(prefix="kduck.security.oauth2.resServer",name="enabled",havingValue = "true")
public class OAuthResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final String RESOURCE_ID = "kduck-oauth2-resource";

    private static List<String> notAuthPathList = new ArrayList<>();

    static {
        notAuthPathList.add("!/oauth/**");
        notAuthPathList.add("!/actuator/**");
        notAuthPathList.add("!/login");
        notAuthPathList.add("!/currentUser");
        notAuthPathList.add("!/mfa/validate");
        notAuthPathList.add("!/oauth2/authorization/**");
        notAuthPathList.add("!/login/oauth2/**");
        notAuthPathList.add("!/user_info");
    }

    @Autowired
    private RoleAccessVoter roleAccessVoter;

    @Autowired
    private KduckSecurityProperties securityProperties;
    //JWT
    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private FrameworkEndpointHandlerMapping endpointHandlerMapping;

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
        voterList.add(roleAccessVoter);

        List<String> arrayList = new ArrayList(notAuthPathList);
        ResServer resServer = securityProperties.getOauth2().getResServer();
        String[] resourcePaths = resServer.getResourcePaths();
        if(resourcePaths == null){
            arrayList.add("any");
        }else{
            arrayList.addAll(Arrays.asList(resourcePaths));
        }
        Collections.sort(arrayList);//主要是把"!"开头（不匹配路径）的路径表达式排到前面。

        //将"/oauth/user_info"排在首位，如果路径是/oauth/user_info则直接返回true，表示该请求由资源服务器自行处理。因为该请求
        //需要校验token并且无不需要进行认证。
        //之所以排在第一个，因为OAuthRequestMatcher过滤器没有那么智能，"!/oauth/**"排在首位会直接排除掉了"/oauth/user_info"
        String[] pathPattern = new String[arrayList.size() + 1];
        pathPattern[0] = "/oauth/user_info";
        System.arraycopy(arrayList.toArray(new String[0]),0,pathPattern,1,arrayList.size());

        http.requestMatcher(new OAuthRequestMatcher(pathPattern));
        // @formatter:off
        http.csrf().disable();
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
