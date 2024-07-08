//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.AuthMethodFilter;

@WebFilter(servletNames = {"activity"})
public class EmptyAuthMethod extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;

}
