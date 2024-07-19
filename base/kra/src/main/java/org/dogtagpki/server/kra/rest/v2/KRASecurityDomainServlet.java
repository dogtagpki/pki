//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.SecurityDomainServlet;
/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "kraSecurityDomain",
        urlPatterns = "/v2/securityDomain/*")
public class KRASecurityDomainServlet extends SecurityDomainServlet {
    private static final long serialVersionUID = 1L;
}
