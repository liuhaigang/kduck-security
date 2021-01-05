package cn.kduck.security.event;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;

public class LogoutSuccessEvent extends AbstractAuthenticationEvent {

//    private HttpServletRequest request;
//    private HttpServletResponse response;

    public LogoutSuccessEvent(Authentication authentication) {
        super(authentication);
    }
}
