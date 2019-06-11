// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.rest;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainResource;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.SecurityDomainProcessor;

/**
 * @author alee
 */
public class SecurityDomainService extends PKIService implements SecurityDomainResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecurityDomainService.class);

    @Override
    public Response getInstallToken(String hostname, String subsystem) {
        logger.debug("SecurityDomainService.getInstallToken(" + hostname + ", " + subsystem + ")");
        try {
            // Get uid from realm authentication.
            String user = servletRequest.getUserPrincipal().getName();

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            InstallToken installToken = processor.getInstallToken(user, hostname, subsystem);
            return createOKResponse(installToken);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response getDomainInfo() throws PKIException {
        try {
            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            DomainInfo domainInfo = processor.getDomainInfo();
            return createOKResponse(domainInfo);

        } catch (PKIException e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw e;

        } catch (Exception e) {
            logger.error("SecurityDomainService: " + e.getMessage(), e);
            throw new PKIException(e.getMessage(), e);
        }
    }
}
