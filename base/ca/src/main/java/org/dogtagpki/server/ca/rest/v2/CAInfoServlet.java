//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.common.CAInfo;
import org.dogtagpki.server.ca.CAEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caInfo",
        urlPatterns = "/v2/info")
public class CAInfoServlet extends CAServlet {
    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(CAInfoServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {"/"})
    public void getInfo(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("CAInfoServlet.get(): session: {}", session.getId());

        CAEngine engine = getCAEngine();
        CAInfo info = engine.getInfo(request.getLocale());

        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }
}
