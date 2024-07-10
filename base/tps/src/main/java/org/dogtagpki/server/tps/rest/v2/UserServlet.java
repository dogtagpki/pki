//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.rest.v2.UserServletBase;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsUser",
        urlPatterns = "/v2/admin/users/*")
public class UserServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserServletBase userServlet = new UserServletBase(getTPSEngine());
        userServlet.get(request, response);
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserServletBase userServlet = new UserServletBase(getTPSEngine());
        userServlet.post(request, response);
    }

    @Override
    public void patch(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserServletBase userServlet = new UserServletBase(getTPSEngine());
        userServlet.patch(request, response);
    }

    @Override
    public void delete(HttpServletRequest request, HttpServletResponse response) throws Exception {
        UserServletBase userServlet = new UserServletBase(getTPSEngine());
        userServlet.delete(request, response);
    }
}
