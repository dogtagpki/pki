//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = {"ocspJobs"})
public class EmptyACL extends ACLFilter {

    private static final long serialVersionUID = 1L;

}
