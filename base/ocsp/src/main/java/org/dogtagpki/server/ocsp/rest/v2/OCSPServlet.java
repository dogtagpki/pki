//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest.v2;

import javax.servlet.ServletContext;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.rest.v2.PKIServlet;

import com.netscape.cmscore.apps.CMSEngine;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class OCSPServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    public OCSPEngine getOCSPEngine() {
        ServletContext servletContext = getServletContext();
        return (OCSPEngine) servletContext.getAttribute("engine");
    }

    @Override
    protected String getSubsystemName() {
        return getOCSPEngine().getID();
    }

    @Override
    protected CMSEngine getEngine() {
        return getOCSPEngine();
    }
}
