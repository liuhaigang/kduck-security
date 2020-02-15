package com.goldgov.kduck.security.access;

import com.goldgov.kduck.security.RoleAccessVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;

/**
 * LiuHG
 */
public abstract class AbstractRoleAccessVoter implements RoleAccessVoter {
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    private AntPathMatcher pathMatcher =  new AntPathMatcher();

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    private boolean isFullyAuthenticated(Authentication authentication) {
        return (!authenticationTrustResolver.isAnonymous(authentication) && !authenticationTrustResolver
                .isRememberMe(authentication));
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        int result = ACCESS_DENIED;

        if(permitAll(collection)){
            return ACCESS_GRANTED;
        }
        if(isFullyAuthenticated(authentication)){
            HttpServletRequest request = ((FilterInvocation) object).getRequest();
            String requestUri = request.getRequestURI();
            String method = request.getMethod();

            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

            //根据当前登录用户所拥有的角色编码查询所拥有的操作权限。
            String[] roleCodes = new String[authorities.size()];
            int i = 0;
            for (GrantedAuthority authority : authorities) {
                roleCodes[i] = authority.getAuthority();
                i++;
            }

            List<ProtectedResource> resourceList = listResourceOperateByCode(roleCodes);
            for (ProtectedResource resource : resourceList) {
                if(pathMatcher.match(resource.getFullPath(),requestUri) && method.equals(resource.getOperateMethod())){
                    result= ACCESS_GRANTED;
                    break;
                }
            }

            if(result == ACCESS_DENIED && permitAll(requestUri,method)){
                result= ACCESS_GRANTED;
            }
        }

        return result;
    }

    /**
     * FIXME 处理匹配路径为"/a/b"和"/a/{b}"的情况，前者不是受保护资源，而后者是，但是后者匹配了前者。目前想到的方式是明确"/a/b"不是受保护资源
     * @param requestUri
     * @param method
     * @return
     */
    private boolean permitAll(String requestUri,String method) {
        //TODO 查询后加入到缓存，内存缓存即可。定时、手动刷新。
        List<ProtectedResource> allList = listAllResourceOperate();
        for (ProtectedResource res : allList) {
            if(res.getOperateMethod().equals(method)){
                if(pathMatcher.match(res.getFullPath(),requestUri)){
                    return false;
                }
            }
        }
        return true;
    }

    private boolean permitAll(Collection<ConfigAttribute> attributes) {
        for (ConfigAttribute attribute : attributes) {
            String attribute1 = attribute.getAttribute();
            if(attribute1 != null && attribute1.equals("permitAll")){
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    public abstract List<ProtectedResource> listResourceOperateByCode(String[] roleCodes);

    public abstract List<ProtectedResource> listAllResourceOperate();
}