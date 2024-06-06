//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.v2.ACLFilter;

@WebFilter(servletNames = {"activity"})
public class EmptyACL extends ACLFilter {

    private static final long serialVersionUID = 1L;

}
