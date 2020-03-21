package com.goldgov.kduck.security.analyzer;

import com.goldgov.kduck.security.RoleAccessVoter;
import com.goldgov.kduck.security.access.AbstractRoleAccessVoter;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.diagnostics.analyzer.AbstractInjectionFailureAnalyzer;

public class MissingRoleAccessFailureAnalyzer extends AbstractInjectionFailureAnalyzer<NoSuchBeanDefinitionException>{

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, NoSuchBeanDefinitionException cause, String description) {
        if(RoleAccessVoter.class.isAssignableFrom(cause.getBeanType())){
            return new FailureAnalysis("当前启用了K-Duck的Security模块，但上下文中缺少必要的访问控制接口实现类。"
                    , "请实现" + RoleAccessVoter.class.getName()+"接口，并定义为一个Spring的Bean对象，并放到可扫描到的路径中。" +
                    "您也可以考虑继承"+ AbstractRoleAccessVoter.class.getName()+"抽象类，仅需要实现必要的接口，减少访问控制逻辑的开发。", cause);
        }
        return null;
    }
}
