//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "tpsProfile")
public class TPSProfileACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAcl("profiles.read");

        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("POST:", "profiles.add");
        aclMap.put("PATCH:{}", "profiles.modify");
        aclMap.put("POST:{}", "profiles.change-status");
        aclMap.put("DELETE:{}", "profiles.remove");
        setAclMap(aclMap);
    }
}
