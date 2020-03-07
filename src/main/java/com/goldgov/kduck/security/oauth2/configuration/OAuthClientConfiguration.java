package com.goldgov.kduck.security.oauth2.configuration;

import com.goldgov.kduck.security.oauth2.matcher.OAuthRequestMatcher;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@Order(300)
@ConditionalOnClass(OAuth2AuthorizedClientService.class)
@ConditionalOnProperty(prefix="kduck.security.oauth2",name="spring-client",havingValue = "true")
public class OAuthClientConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(new OAuthRequestMatcher(new String[]{"!/oauth/**","!/currentUser","any"}));
        http.csrf().disable();

        http.cors().and().authorizeRequests().anyRequest().authenticated()//.accessDecisionManager(new AffirmativeBased(voterList))
                .and().oauth2Login().and().oauth2Client();
    }

//    @Bean
//    @Override
//    public AuthenticationManager authenticationManagerBean() throws Exception {
//        AuthenticationManager manager = super.authenticationManagerBean();
//        return manager;
//    }

    @Configuration
    @RestController
    public class ClientUserRest {

        @Autowired
        private OAuth2AuthorizedClientService authorizedClientService;

        @RequestMapping("/user_info")
        @ResponseBody
        public JsonObject userInfo(OAuth2AuthenticationToken authentication) {
            OAuth2AuthorizedClient authorizedClient =
                    this.authorizedClientService.loadAuthorizedClient(
                            authentication.getAuthorizedClientRegistrationId(),
                            authentication.getName());

//            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//            System.out.println(accessToken);
            return new JsonObject(authorizedClient.getAccessToken());
        }
    }
}
