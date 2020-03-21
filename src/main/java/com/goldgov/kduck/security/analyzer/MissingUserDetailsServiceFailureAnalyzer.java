package com.goldgov.kduck.security.analyzer;

import com.goldgov.kduck.security.RoleAccessVoter;
import com.goldgov.kduck.security.access.AbstractRoleAccessVoter;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.analyzer.AbstractInjectionFailureAnalyzer;
import org.springframework.security.core.userdetails.UserDetailsService;

public class MissingUserDetailsServiceFailureAnalyzer extends AbstractInjectionFailureAnalyzer<NoSuchBeanDefinitionException> {
    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, NoSuchBeanDefinitionException cause, String description) {
        if(UserDetailsService.class.isAssignableFrom(cause.getBeanType())){
            return new FailureAnalysis("当前启用了K-Duck的Security模块，但上下文中缺少必要的用户明细接口实现类。"
                    , "请实现" + UserDetailsService.class.getName()+"接口，并定义为一个Spring的Bean对象，并放到可扫描到的路径中。", cause);
        }
        return null;
    }
}
