package com.goldgov.kduck.security.web;

import com.goldgov.kduck.dao.ParamMap;
import com.goldgov.kduck.security.AuthUser;
import com.goldgov.kduck.security.UserExtInfo;
import com.goldgov.kduck.service.ValueMap;
import com.goldgov.kduck.web.json.JsonObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * LiuHG
 */
@RestController
public class SecurityController {

    @Autowired(required = false)
    private UserExtInfo userExtInfo;


    @GetMapping(value = "/currentUser")
    public JsonObject currentUserName(Authentication principal) {
        if(principal == null) return new JsonObject("_ANONYMOUS_");
        if(userExtInfo != null){
            AuthUser user = (AuthUser) principal.getPrincipal();
            ValueMap userExtInfo = this.userExtInfo.getUserExtInfo(user);
            if(userExtInfo == null){
                throw new RuntimeException("获取用户的扩展信息不能为null" + user.getUserId());
            }
            return new JsonObject(userExtInfo);
        }
        return new JsonObject(ParamMap.create("userName",principal.getName()).toMap());
    }
}
