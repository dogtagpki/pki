//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.server.rest.SecurityDomainService;

import com.netscape.certsrv.base.EBaseException;

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
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}
