package com.goldgov.kduck.security.web;

import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * LiuHG
 */
@RestController
public class LocalUserInfoController {

    @GetMapping(value = "/currentUser")
    public JsonObject currentUserName(Authentication principal) {
        if(principal == null) return new JsonObject("_ANONYMOUS_");
        return new JsonObject(principal.getPrincipal(),0,"Authorized");
//        if(userExtInfo != null){
//            AuthUser user = (AuthUser) principal.getPrincipal();
//            ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(user);
//            if(userExtInfo == null){
//                throw new RuntimeException("获取用户的扩展信息不能为null" + user.getUserId());
//            }
//            AuthUser authUser = AuthUserHolder.getAuthUser();
//            return new JsonObject(authUser);
//        }
//        return new JsonObject(ParamMap.create("userName",principal.getName()).toMap());
    }
}
