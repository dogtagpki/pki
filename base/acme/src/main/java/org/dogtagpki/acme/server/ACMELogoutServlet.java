//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * ACME Logout.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeLogoutServlet",
        urlPatterns = "/logout/*")
public class ACMELogoutServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMELogoutServlet.class);

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession(false);

        if (session != null) {
            logger.info("ACMELogoutServlet: Destroying session " + session.getId());
            session.invalidate();
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        return;

    }
}
