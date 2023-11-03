//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.rest;

import org.dogtagpki.server.kra.KRAEngine;
import org.dogtagpki.server.kra.KRAEngineConfig;
import org.dogtagpki.server.rest.SecurityDomainService;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;

/**
 * @author Endi S. Dewata
 */
public class KRASecurityDomainService extends SecurityDomainService {

    @Override
    public boolean isEnabled() {

        KRAEngine engine = KRAEngine.getInstance();
        KRAEngineConfig engineConfig = engine.getConfig();

        try {
            // standalone KRA should provide security domain services
            return engineConfig.getBoolean("kra.standalone", false);

        } catch (EBaseException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }
}
