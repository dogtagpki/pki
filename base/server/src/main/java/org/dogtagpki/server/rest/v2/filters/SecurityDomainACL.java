package org.dogtagpki.server.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;

public class SecurityDomainACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("GET:installToken", "securityDomain.read");
        aclMap.put("PUT:hosts", "securityDomain.modify");
        aclMap.put("DELETE:hosts/{}", "securityDomain.modify");
        setAclMap(aclMap);
    }
}
