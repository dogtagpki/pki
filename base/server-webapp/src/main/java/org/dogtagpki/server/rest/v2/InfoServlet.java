//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.common.Info;
import org.dogtagpki.server.PKIEngine;
import org.dogtagpki.server.PKIServlet;

import com.netscape.certsrv.base.MediaType;

/**
 * @author Endi S. Dewata
 */
@WebServlet("/v2/info")
public class InfoServlet extends PKIServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {

        PKIEngine engine = getPKIEngine();
        Info info = engine.getInfo(request);

        response.setContentType(MediaType.APPLICATION_JSON);

        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }
}
