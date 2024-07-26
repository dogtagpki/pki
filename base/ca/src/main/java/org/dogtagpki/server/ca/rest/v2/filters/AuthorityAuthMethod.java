//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "caAuthority")
public class AuthorityAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;

    private static final String AUTHORITIES = "authorities";

    @Override
    public void init() throws ServletException {
        Map<String, String> authMethodMap = new HashMap<>();
        authMethodMap.put("POST:", AUTHORITIES);
        authMethodMap.put("PUT:{}", AUTHORITIES);
        authMethodMap.put("DELETE:{}", AUTHORITIES);
        authMethodMap.put("POST:{}/enable", AUTHORITIES);
        authMethodMap.put("POST:{}/disable", AUTHORITIES);
        authMethodMap.put("POST:{}/renew", AUTHORITIES);
        setAuthMethodMap(authMethodMap);
    }
}
