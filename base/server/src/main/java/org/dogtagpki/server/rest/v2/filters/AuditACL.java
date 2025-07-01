package org.dogtagpki.server.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;

public class AuditACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAcl("audit.read");
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("GET:", "audit.read");
        aclMap.put("PATCH:", "audit.modify");
        aclMap.put("POST:", "audit.modify");
        aclMap.put("GET:files", "audit-log.read");
        aclMap.put("GET:files/{}", "audit-log.read");
        setAclMap(aclMap);
    }
}
