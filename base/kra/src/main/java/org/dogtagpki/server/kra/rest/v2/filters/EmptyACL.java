//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = {"kraInfo", "kraJobs", "kraSystemCert"})
public class EmptyACL extends ACLFilter {

    private static final long serialVersionUID = 1L;

}
