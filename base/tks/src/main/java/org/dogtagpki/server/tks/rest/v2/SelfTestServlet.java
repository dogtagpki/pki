//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.rest.v2.SelfTestServletBase;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tksSelfTests",
        urlPatterns = "/v2/selftests/*")
public class SelfTestServlet extends TKSServlet {
    private static final long serialVersionUID = 1L;

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTKSEngine());
        selfTestServlet.get(request, response);
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        SelfTestServletBase selfTestServlet = new SelfTestServletBase(getTKSEngine());
        selfTestServlet.post(request, response);
    }

}
