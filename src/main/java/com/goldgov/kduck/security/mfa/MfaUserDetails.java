package com.goldgov.kduck.security.mfa;

import java.util.Map;

public interface MfaUserDetails {

    String getUsername();
    String[] getType();
    String getSecret();
    Map<String,Object> getDetails();


    class SimpleMfaUserDetails implements MfaUserDetails{

        private String username;
        private String[] type;
        private String secret;
        private Map<String, Object> details;

        public void setUsername(String username) {
            this.username = username;
        }

        public void setType(String[] type) {
            this.type = type;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public void setDetails(Map<String, Object> details) {
            this.details = details;
        }

        @Override
        public String getUsername() {
            return username;
        }

        @Override
        public String[] getType() {
            return type;
        }

        @Override
        public String getSecret() {
            return secret;
        }

        @Override
        public Map<String, Object> getDetails() {
            return details;
        }
    }

}
