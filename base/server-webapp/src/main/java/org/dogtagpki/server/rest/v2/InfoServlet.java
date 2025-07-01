//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.MediaType;

import org.dogtagpki.common.Info;
import org.dogtagpki.server.PKIEngine;
import org.dogtagpki.server.PKIServlet;

import com.netscape.certsrv.base.MimeType;

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

        response.setContentType(MimeType.APPLICATION_JSON);

        PrintWriter out = response.getWriter();
        out.println(info.toJSON());
    }
}
