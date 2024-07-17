//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2;

import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.SelfTestServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "ocspSelfTests",
        urlPatterns = "/v2/selftests/*")
public class SelfTestOCSPServlet extends SelfTestServlet {
    private static final long serialVersionUID = 1L;
}
