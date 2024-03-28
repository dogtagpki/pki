//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.v2.AuthMethodFilter;

@WebFilter(servletNames = {"caInfo", "caCert", "caCertRequest"})
public class EmptyAuthMethod extends AuthMethodFilter {

    private static final long serialVersionUID = 1L;

}
