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
package com.netscape.cms.servlet.csadmin;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.InstallToken;
import com.netscape.certsrv.system.SecurityDomainResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author alee
 */
public class SecurityDomainService extends PKIService implements SecurityDomainResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    @Override
    public InstallToken getInstallToken(String hostname, String subsystem) {
        try {
            // Get uid from realm authentication.
            String user = servletRequest.getUserPrincipal().getName();

            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            return processor.getInstallToken(user, hostname, subsystem);

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public DomainInfo getDomainInfo() throws PKIException {
        try {
            SecurityDomainProcessor processor = new SecurityDomainProcessor(getLocale(headers));
            return processor.getDomainInfo();

        } catch (EBaseException e) {
            throw new PKIException(e.getMessage(), e);
        }
    }
}
