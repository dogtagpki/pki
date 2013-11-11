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
package com.netscape.cms.servlet.admin;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.system.KRAConnectorResource;
import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Ade Lee
 */
public class KRAConnectorService extends PKIService implements KRAConnectorResource {

    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    @Override
    public void addConnector(KRAConnectorInfo info) {

        if (info == null) throw new BadRequestException("KRA connector info is null.");

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.addConnector(info);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void removeConnector(String host, String port) {

        if (host == null) throw new BadRequestException("KRA connector host is null.");
        if (port == null) throw new BadRequestException("KRA connector port is null.");

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.removeConnector(host, port);
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public void addConnector(MultivaluedMap<String, String> form) {
        KRAConnectorInfo info = new KRAConnectorInfo(form);
        addConnector(info);
    }

}
