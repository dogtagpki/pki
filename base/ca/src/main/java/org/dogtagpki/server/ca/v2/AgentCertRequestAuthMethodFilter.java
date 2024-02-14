//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.v2.AuthMethodFilter;

@WebFilter(servletNames = "caCertRequest-agent")
public class AgentCertRequestAuthMethodFilter extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        super.init();
        setAuthMethod("certrequests");
    }

}
