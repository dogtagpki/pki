//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSSubsystem;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class TPSServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    @Override
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    @Override
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }


    protected TPSEngine getTPSEngine() {
        ServletContext servletContext = getServletContext();
        return (TPSEngine) servletContext.getAttribute("engine");
    }

    protected TPSSubsystem getTPSSubsystem() {
        ServletContext servletContext = getServletContext();
        TPSEngine engine = (TPSEngine) servletContext.getAttribute("engine");

        return (TPSSubsystem) engine.getSubsystem(TPSSubsystem.ID);
    }
}
