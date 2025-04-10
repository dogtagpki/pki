//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2.filters;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "tpsProfileMapping")
public class ProfileMappingACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAcl("profile-mappings.read");

        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("POST:", "profile-mappings.add");
        aclMap.put("PATCH:{}", "profile-mappings.modify");
        aclMap.put("POST:{}", "profiles-mappings.change-status");
        aclMap.put("DELETE:{}", "profile-mappings.remove");
        setAclMap(aclMap);
    }
}
