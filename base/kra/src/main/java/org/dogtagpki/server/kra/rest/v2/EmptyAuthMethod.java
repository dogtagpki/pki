//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.AuthMethodFilter;

@WebFilter(servletNames = {"kraAccount", "kraJobs"})
public class EmptyAuthMethod extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;

}
