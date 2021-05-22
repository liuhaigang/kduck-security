package cn.kduck.security.listener;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextListener;

import javax.servlet.ServletRequestEvent;

@Component
public class LocaleRequestContextListener extends RequestContextListener {

    @Override
    public void requestInitialized(ServletRequestEvent requestEvent) {
        super.requestInitialized(requestEvent);
//        HttpServletRequest request = (HttpServletRequest) requestEvent.getServletRequest();
//        LocaleContextHolder.setLocale(request.getParameter(""));
    }
}
