//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.rest;

import org.dogtagpki.server.ocsp.OCSPEngine;
import org.dogtagpki.server.ocsp.OCSPEngineConfig;
import org.dogtagpki.server.rest.SecurityDomainService;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;

/**
 * @author Endi S. Dewata
 */
public class OCSPSecurityDomainService extends SecurityDomainService {

    @Override
    public boolean isEnabled() {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPEngineConfig engineConfig = engine.getConfig();

        try {
            // standalone OCSP should provide security domain services
            return engineConfig.getBoolean("ocsp.standalone", false);

        } catch (EBaseException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }
}
