package cn.kduck.security.oauth2.configuration;

import cn.kduck.security.KduckSecurityProperties;
import cn.kduck.security.KduckSecurityProperties.OAuth2Config;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.sql.DataSource;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Map;

@Configuration
public class TokenConfiguration {


    private final KduckSecurityProperties securityProperties;

    public TokenConfiguration(KduckSecurityProperties securityProperties){
        this.securityProperties = securityProperties;
    }

    @Bean
    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "jwt",matchIfMissing=true)
    public JwtAccessTokenConverter accessTokenConverter() {
        String jwtKey = OAuth2Config.DEFAULT_JWT_KEY;
        if(securityProperties.getOauth2() != null && securityProperties.getOauth2().getJwtKey() != null){
            jwtKey = securityProperties.getOauth2().getJwtKey();
        }
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        converter.setSigningKey(jwtKey);
        converter.setKeyPair(keyPair());
        return converter;
    }

    @Bean
//    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "jwt",matchIfMissing=true)
    @ConditionalOnBean(JwtTokenExtInfo.class)
    public TokenEnhancer tokenEnhancer(JwtTokenExtInfo jwtTokenExtInfo) {
        return (accessToken, authentication) -> {
            Map<String, Object> info = jwtTokenExtInfo.extInfo(accessToken,authentication);
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
            return accessToken;
        };
    }

    @Bean
    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "jwt",matchIfMissing=true)
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "memory")
    public TokenStore memoryTokenStore() {
        return new InMemoryTokenStore();
    }

//    @Bean
//    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "redis")
//    public TokenStore redisTokenStore(RedisConnectionFactory redisConnectionFactory) {
//        return new RedisTokenStore(redisConnectionFactory);
//    }

    @Bean
    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "jdbc")
    public TokenStore jdbcTokenStore(DataSource dataSource) {
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    public KeyPair keyPair() {
        try {
            String privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
            String modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
            String exponent = "65537";

            RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
            RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));
        } catch ( Exception e ) {
            throw new IllegalArgumentException(e);
        }
    }

    @Configuration
    @ConditionalOnClass(RedisConnectionFactory.class)
    @ConditionalOnProperty(prefix="kduck.security.oauth2",name="tokenStore",havingValue = "redis")
    public static class RedisTokenConfiguration{

        @Bean
        public TokenStore redisTokenStore(RedisConnectionFactory redisConnectionFactory) {
            return new RedisTokenStore(redisConnectionFactory);
        }
    }

}
