package cn.kduck.security.mfa.send;

import cn.kduck.security.mfa.MfaUserDetails;

/**
 * 授权码发送策略，实现该接口将授权码发送给指定用户
 * @author LiuHG
 */
public interface MfaSendStrategy {

    /**
     * 发送类型的编码，与配置中的"kduck.security.mfa.sendStrategy"参数对应。
     * @return 发送类型的编码
     */
    String sendType();

    /**
     * 授权码发送，根据业务需求定制发送策略。
     * @param userDetails 用户信息对象
     * @param otp 授权码
     */
    void send(MfaUserDetails userDetails, String otp);
}
