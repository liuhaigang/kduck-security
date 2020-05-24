package com.goldgov.kduck.security.listener;

import com.goldgov.kduck.cache.CacheHelper;
import com.goldgov.kduck.security.callback.AuthenticationFailCallback;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class AuthenticationFailListener implements ApplicationListener<AbstractAuthenticationFailureEvent> {

    public static final String AUTHENTICATION_FAIL_CAHCE_NAME = "AUTHENTICATION_FAIL_CAHCE_NAME";
    public static final long MAX_LOCK_DURATION_SECONDS = 3*60*60*1000;

    @Autowired(required = false)
    private List<AuthenticationFailCallback> callbackList;

    @Override
    public void onApplicationEvent(AbstractAuthenticationFailureEvent event) {
        AuthenticationException exception = event.getException();
        Authentication authentication = event.getAuthentication();

        AuthenticationFailRecord failRecord = null;
        if(authentication instanceof UsernamePasswordAuthenticationToken &&
                exception instanceof BadCredentialsException){
            String accountName = authentication.getName();
            failRecord = processFailRecord(accountName);
        }

        if(callbackList != null){
            for (AuthenticationFailCallback callback : callbackList) {
                callback.doHandle(authentication,exception,failRecord);
            }
        }
    }

    private AuthenticationFailRecord processFailRecord(String accountName){
//        Integer count = CacheHelper.getByCacheName(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,Integer.class);
//        count = count == null ? 1 : ++count;
//        if(count.intValue() == 1){
//            CacheHelper.put(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,count,600);//FIXME seconds to config
//        }else{
//            CacheHelper.put(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,count);
//        }

        AuthenticationFailRecord failRecord = CacheHelper.getByCacheName(AUTHENTICATION_FAIL_CAHCE_NAME,accountName,AuthenticationFailRecord.class);

        if(failRecord == null){
            failRecord = new AuthenticationFailRecord(accountName, new Date());
        }else{
            failRecord.addFailDate(new Date());
        }

        //将登录失败对象放到缓存中，默认最长存放3小时，即3小时后会自动清除失败次数信息
        //改缓存仅为AuthenticationFailureStrategyFilter提供服务
        CacheHelper.put(AUTHENTICATION_FAIL_CAHCE_NAME, accountName, failRecord,MAX_LOCK_DURATION_SECONDS);
        return failRecord;
    }

    public static class AuthenticationFailRecord {
        private List<Date> failDateList = new ArrayList<>();
        private String accountName;

        //just for serializable
        public AuthenticationFailRecord(){}

        public AuthenticationFailRecord(String accountName,Date failDate) {
            this.accountName = accountName;
            failDateList.add(failDate);
        }

        public void addFailDate(Date date){
            failDateList.add(date);
        }

        public int getFailTotalNum(){
            return failDateList.size();
        }

        public String getAccountName() {
            return accountName;
        }

        public List<Date> getFailDateList() {
            return failDateList;
        }

        public void setFailDateList(List<Date> failDateList) {
            this.failDateList = failDateList;
        }

        public void setAccountName(String accountName) {
            this.accountName = accountName;
        }


        public int getFailNumByBeforeMinutes(int minutes){
            long beforeTime = System.currentTimeMillis() - minutes * 60 * 1000;
            return getFailNumByAfterDate(new Date(beforeTime));
        }

        public int getFailNumByAfterDate(Date afterDate){
            Date[] dates = failDateList.toArray(new Date[0]);
            int failTotal = dates.length;
            for (int i = 0; i < dates.length; i++) {
                if(dates[i].after(afterDate)){
                    return failTotal - i;
                }
            }
            return 0;
        }
    }

//    @Component
//    public static class AuthenticationSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {
//        @Override
//        public void onApplicationEvent(InteractiveAuthenticationSuccessEvent event) {
//            Authentication authentication = event.getAuthentication();
//            if(authentication instanceof UsernamePasswordAuthenticationToken){
//                CacheHelper.evict(AUTHENTICATION_FAIL_CAHCE_NAME,authentication.getName());
//            }
//        }
//    }
}
