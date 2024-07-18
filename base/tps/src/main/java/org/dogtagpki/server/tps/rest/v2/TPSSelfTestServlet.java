//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.SelfTestServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsSelfTests",
        urlPatterns = "/v2/selftests/*")
public class TPSSelfTestServlet extends SelfTestServlet {
    private static final long serialVersionUID = 1L;
}
