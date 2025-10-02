//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "caAuthority")
public class AuthorityACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    private static final String CREATE = "authorities.create";
    private static final String MODIFY = "authorities.modify";
    private static final String DELETE = "authorities.delete";

    @Override
    public void init() throws ServletException {
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("POST:", CREATE);
        aclMap.put("PUT:{}", MODIFY);
        aclMap.put("DELETE:{}", DELETE);
        aclMap.put("POST:{}/enable", MODIFY);
        aclMap.put("POST:{}/disable", MODIFY);
        aclMap.put("POST:{}/renew", MODIFY);
        setAclMap(aclMap);
    }
}
