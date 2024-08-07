//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest.v2;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.dogtagpki.server.rest.v2.PKIServlet;

import com.netscape.certsrv.security.IStorageKeyUnit;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class KRAServlet extends PKIServlet {
    public static final long serialVersionUID = 1L;

    protected KRAEngine engine;
    protected KRAEngineConfig config;
    protected IStorageKeyUnit storageUnit;

    @Override
    public void init() throws ServletException {
        super.init();

        engine = getKRAEngine();
        config = engine.getConfig();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        storageUnit = kra.getStorageKeyUnit();
    }

    public KRAEngine getKRAEngine() {
        ServletContext servletContext = getServletContext();
        return (KRAEngine) servletContext.getAttribute("engine");
    }
}
