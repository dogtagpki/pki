//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.rest.v2.PKIServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class CAServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;
    protected CAEngine engine;

    @Override
    public void init() throws ServletException {
        super.init();
        engine = getCAEngine();
    }


    public CAEngine getCAEngine() {
        if (engine != null)
            return engine;
        ServletContext servletContext = getServletContext();
        return (CAEngine) servletContext.getAttribute("engine");
    }
}
