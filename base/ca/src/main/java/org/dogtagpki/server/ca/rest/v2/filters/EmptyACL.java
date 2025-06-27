//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = {"caInfo", "caCert", "caCertRequest", "caJobs", "caFeature", "caSystemCert", "caInstallerServlet"})
public class EmptyACL extends ACLFilter {

    private static final long serialVersionUID = 1L;

}
