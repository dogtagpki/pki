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

@WebFilter(servletNames = "tpsConnector")
public class ConnectorACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    @Override
    public void init() throws ServletException {
        setAcl("connectors.read");
        Map<String, String> aclMap = new HashMap<>();
        aclMap.put("POST:", "connectors.add");
        aclMap.put("PATCH:{}", "connectors.modify");
        aclMap.put("POST:{}", "connectors.change-status");
        aclMap.put("DELETE:{}", "connectors.remove");

        setAclMap(aclMap);
    }

}
