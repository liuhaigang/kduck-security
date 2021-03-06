package cn.kduck.security.access;

import cn.kduck.security.RoleAccessVoter;
import cn.kduck.security.mfa.MfaAuthenticationToken;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

/**
 * LiuHG
 */
public abstract class AbstractRoleAccessVoter implements RoleAccessVoter {
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    private boolean isFullyAuthenticated(Authentication authentication) {
        return (!authenticationTrustResolver.isAnonymous(authentication) && !authenticationTrustResolver
                .isRememberMe(authentication)) && !(authentication instanceof MfaAuthenticationToken);
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
        int result = ACCESS_DENIED;

        if(permitAll(collection)){
            return ACCESS_GRANTED;
        }
        if(isFullyAuthenticated(authentication)){
            HttpServletRequest request = ((FilterInvocation) object).getRequest();
//            String requestUri = request.getRequestURI();
//            String method = request.getMethod();

            if(checkAuthorize(authentication,request)){
                result= ACCESS_GRANTED;
            }else{
                result= ACCESS_DENIED;
            }

//            List<ProtectedResource> resourceList = listResourceOperateByCode(authentication);
//            for (ProtectedResource resource : resourceList) {
//                if(pathMatcher.match(resource.getFullPath(),requestUri) && method.equals(resource.getOperateMethod())){
//                    result= ACCESS_GRANTED;
//                    break;
//                }
//            }
//
//            if(result == ACCESS_DENIED && permitAll(requestUri,method)){
//                result= ACCESS_GRANTED;
//            }
        }

        return result;
    }

//    /**
//     * FIXME ?????????????????????"/a/b"???"/a/{b}"?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????"/a/b"?????????????????????
//     * @param requestUri
//     * @param method
//     * @return
//     */
//    private boolean permitAll(String requestUri,String method) {
//        //TODO ????????????????????????????????????????????????????????????????????????
//        List<ProtectedResource> allList = listAllResourceOperate();
//        for (ProtectedResource res : allList) {
//            if(res.getOperateMethod().equals(method)){
//                if(pathMatcher.match(res.getFullPath(),requestUri)){
//                    return false;
//                }
//            }
//        }
//        return true;
//    }

    private boolean permitAll(Collection<ConfigAttribute> attributes) {
        for (ConfigAttribute attribute : attributes) {
            if(attribute.toString().equals("permitAll")){
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    public abstract boolean checkAuthorize(Authentication authentication,HttpServletRequest request);

}
