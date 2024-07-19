package org.dogtagpki.server.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;

public class SecurityDomainAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        Map<String, String> authMethodMap = new HashMap<>();
        authMethodMap.put("GET:installToken", "securityDomain.installToken");
        setAuthMethodMap(authMethodMap);
    }
}
