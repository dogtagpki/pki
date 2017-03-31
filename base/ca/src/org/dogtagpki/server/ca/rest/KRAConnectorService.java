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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.system.KRAConnectorResource;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Ade Lee
 */
public class KRAConnectorService extends PKIService implements KRAConnectorResource {

    @Override
    public Response addConnector(KRAConnectorInfo info) {

        if (info == null) throw new BadRequestException("Missing KRA connector info.");

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.addConnector(info);
            return createNoContentResponse();
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response addHost(String host, String port) {
        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.addHost(host, port);
            return createNoContentResponse();
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response removeConnector(String host, String port) {

        if (host == null) throw new BadRequestException("Missing KRA connector host.");
        if (port == null) throw new BadRequestException("Missing KRA connector port.");

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.removeConnector(host, port);
            return createNoContentResponse();
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getConnectorInfo() {

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            return createOKResponse(processor.getConnectorInfo());
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException(e.getMessage());
        }
    }

}
