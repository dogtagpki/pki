//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "caCertRequest-agent")
public class AgentCertRequestAuthMethod extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAuthMethod("certrequests");
    }

}
