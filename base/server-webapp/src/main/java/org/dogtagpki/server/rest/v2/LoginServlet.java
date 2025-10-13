//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.server.PKIServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
@WebServlet("/v2/login")
public class LoginServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(LoginServlet.class);



    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("LoginService.login(): session: {}", session.getId());

        // mark banner displayed in this session
        session.setAttribute("bannerDisplayed", "true");
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);;
    }
}
