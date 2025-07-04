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
package org.dogtagpki.server.ca.rest.v1;

import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;

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

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAConnectorService.class);

    @Override
    public Response addConnector(KRAConnectorInfo info) {

        if (info == null) throw new BadRequestException("Missing KRA connector info.");

        CAEngine engine = (CAEngine) getCMSEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

            processor.addConnector(info);
            return createNoContentResponse();
        } catch (EBaseException e) {
            String message = "Unable to add KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
    }

    @Override
    public Response addHost(String host, String port) {

        CAEngine engine = (CAEngine) getCMSEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

            processor.addHost(host, port);
            return createNoContentResponse();
        } catch (EBaseException e) {
            String message = "Unable to add KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
    }

    @Override
    public Response removeConnector(String host, String port) {

        if (host == null) throw new BadRequestException("Missing KRA connector host.");
        if (port == null) throw new BadRequestException("Missing KRA connector port.");

        CAEngine engine = (CAEngine) getCMSEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

            processor.removeConnector(host, port);
            return createNoContentResponse();
        } catch (EBaseException e) {
            String message = "Unable to remove KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
    }

    @Override
    public Response getConnectorInfo() {

        CAEngine engine = (CAEngine) getCMSEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

            return createOKResponse(processor.getConnectorInfo());
        } catch (EBaseException e) {
            String message = "Unable to get KRA connector: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }
    }

}
