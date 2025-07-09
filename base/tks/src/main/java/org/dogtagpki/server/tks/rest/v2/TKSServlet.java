//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tks.TKSEngine;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class TKSServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    protected TKSEngine engine;

    @Override
    public void init() throws ServletException {
        super.init();

        engine = getTKSEngine();
    }


    public TKSEngine getTKSEngine() {
        ServletContext servletContext = getServletContext();
        return (TKSEngine) servletContext.getAttribute("engine");
    }
}
