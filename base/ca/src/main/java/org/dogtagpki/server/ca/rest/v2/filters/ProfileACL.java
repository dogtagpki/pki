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

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "caProfile")
public class ProfileACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    private static final String LIST = "profiles.list";
    private static final String READ = "profiles.read";
    private static final String CREATE = "profiles.create";
    private static final String APPROVE = "profiles.approve";
    private static final String MODIFY = "profiles.modify";
    private static final String DELETE = "profiles.delete";

    @Override
    public void init() throws ServletException {
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("GET:", LIST);
        aclMap.put("GET:{}", READ);
        aclMap.put("GET:{}/raw", READ);
        aclMap.put("POST:", CREATE);
        aclMap.put("POST:raw", CREATE);
        aclMap.put("POST:{}", APPROVE);
        aclMap.put("PUT:{}", MODIFY);
        aclMap.put("PUT:{}/raw", MODIFY);
        aclMap.put("DELETE:{}", DELETE);
        setAclMap(aclMap);
    }
}
