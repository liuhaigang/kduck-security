package cn.kduck.security;

import org.springframework.security.core.GrantedAuthority;

/**
 * LiuHG
 */
public class ResourceGrantedAuthority implements GrantedAuthority {

    private final String resouce;
    private final String operate;

    public ResourceGrantedAuthority(String resouce, String operate){
        this.resouce = resouce;
        this.operate = operate;
    }

    @Override
    public String getAuthority() {
        return resouce + "#" + operate;
    }

    public String getResouce() {
        return resouce;
    }

    public String getOperate() {
        return operate;
    }
}
