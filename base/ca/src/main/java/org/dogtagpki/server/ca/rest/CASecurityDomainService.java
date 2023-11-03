//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.server.rest.SecurityDomainService;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;

/**
 * @author Endi S. Dewata
 */
public class CASecurityDomainService extends SecurityDomainService {

    @Override
    public boolean isEnabled() {

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig engineConfig = engine.getConfig();

        try {
            // if the server creates a new security domain (instead of joining
            // an existing one) it should provide security domain services
            String select = engineConfig.getString("securitydomain.select");
            return "new".equals(select);

        } catch (EBaseException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }
}
