package com.goldgov.kduck.security.access;

public class ProtectedResource {
    private final String fullPath;
    private final String operateMethod;


    public ProtectedResource(String fullPath, String operateMethod) {
        this.fullPath = fullPath;
        this.operateMethod = operateMethod;
    }

    public String getFullPath() {
        return fullPath;
    }

    public String getOperateMethod() {
        return operateMethod;
    }
}
