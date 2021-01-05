package cn.kduck.security.mfa;

import java.util.Map;

public interface MfaUserDetails {

    String getUsername();
    String getSecret();
    String getMail();
    String getPhone();
    Map<String,Object> getDetails();


    class SimpleMfaUserDetails implements MfaUserDetails{

        private String username;
        private String secret;
        private String mail;
        private String phone;
        private Map<String, Object> details;

        public void setUsername(String username) {
            this.username = username;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public void setDetails(Map<String, Object> details) {
            this.details = details;
        }

        public void setMail(String mail) {
            this.mail = mail;
        }

        public void setPhone(String phone) {
            this.phone = phone;
        }

        @Override
        public String getMail() {
            return mail;
        }

        @Override
        public String getPhone() {
            return phone;
        }

        @Override
        public String getUsername() {
            return username;
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
