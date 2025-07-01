//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2;

import jakarta.servlet.ServletContext;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.rest.v2.PKIServlet;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class OCSPServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    public OCSPEngine getOCSPEngine() {
        ServletContext servletContext = getServletContext();
        return (OCSPEngine) servletContext.getAttribute("engine");
    }
}
