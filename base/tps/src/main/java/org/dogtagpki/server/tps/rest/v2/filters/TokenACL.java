package org.dogtagpki.server.tps.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "token")
public class TokenACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    private static final String ADD = "tokens.add";
    private static final String MODIFY = "tokens.modify";
    private static final String REMOVE = "tokens.remove";

    @Override
    public void init() throws ServletException {
        setAcl("tokens.read");
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("POST:/", ADD);
        aclMap.put("PUT:/{}", MODIFY);
        aclMap.put("PATCH:/{}", MODIFY);
        aclMap.put("POST:/{}", MODIFY);
        aclMap.put("DELETE:/{}", REMOVE);

        setAclMap(aclMap);
    }
}
