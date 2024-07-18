//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.rest.v2;

import javax.servlet.ServletContext;

import org.dogtagpki.server.rest.v2.PKIServlet;
import org.dogtagpki.server.tks.TKSEngine;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class TKSServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    public TKSEngine getTKSEngine() {
        ServletContext servletContext = getServletContext();
        return (TKSEngine) servletContext.getAttribute("engine");
    }
}
