//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import javax.servlet.annotation.WebServlet;

import org.dogtagpki.server.rest.v2.GroupServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tksGroup",
        urlPatterns = "/v2/admin/groups/*")
public class TKSGroupServlet extends GroupServlet {
    private static final long serialVersionUID = 1L;
}
