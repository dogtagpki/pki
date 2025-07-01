package org.dogtagpki.server.tks.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "tksTPSConnector")
public class TPSConnectorACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    private static final String ADMIN_SHARED_SECRET = "admin.sharedsecret";

    @Override
    public void init() throws ServletException {
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("GET:{}/shared-secret", ADMIN_SHARED_SECRET);
        aclMap.put("POST:{}/shared-secret", ADMIN_SHARED_SECRET);
        aclMap.put("PUT:{}/shared-secret", ADMIN_SHARED_SECRET);
        aclMap.put("DELETE:{}/shared-secret", ADMIN_SHARED_SECRET);
        setAclMap(aclMap);
    }
}
