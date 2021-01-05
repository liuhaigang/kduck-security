package cn.kduck.security.mfa;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class MfaAuthenticationToken implements Authentication {

        private Authentication embeddedToken;

	public MfaAuthenticationToken(Authentication auth) {
            embeddedToken = auth;
        }

        public Authentication getEmbeddedToken() {
            return embeddedToken;
        }

        @Override
        public String getName() {
            return embeddedToken.getName();
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            Set<GrantedAuthority> authorities = new HashSet<GrantedAuthority>();
            return authorities;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return embeddedToken.getDetails();
        }

        @Override
        public Object getPrincipal() {
            return embeddedToken.getPrincipal();
        }

        @Override
        public boolean isAuthenticated() {
            return embeddedToken.isAuthenticated();
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            embeddedToken.setAuthenticated(isAuthenticated);
        }
}
