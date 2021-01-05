package cn.kduck.security.callback;

import cn.kduck.security.listener.AuthenticationFailListener.AuthenticationFailRecord;
import org.springframework.security.core.Authentication;

/**
 * LiuHG
 */
public interface AuthenticationFailCallback {

    void doHandle(Authentication authentication, Exception exception, AuthenticationFailRecord failRecord);
}
