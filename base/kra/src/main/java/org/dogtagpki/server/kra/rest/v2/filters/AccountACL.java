package org.dogtagpki.server.kra.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.ACLFilter;

@WebFilter(servletNames = "kraAccount")
public class AccountACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAcl("account.login");
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("GET:/login", "account.login");
        aclMap.put("GET:/logout", "account.logout");
        setAclMap(aclMap);
    }
}
