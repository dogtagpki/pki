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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps;

import java.io.ByteArrayInputStream;
import java.net.URI;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.xml.XMLObject;

public class TPSConfigurator extends Configurator {

    public TPSConfigurator(CMSEngine engine) {
        super(engine);
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) throws Exception {

        URI secdomainURI = new URI(request.getSecurityDomainUri());
        URI caURI = request.getCaUri();
        URI tksURI = request.getTksUri();
        URI kraURI = request.getKraUri();

        try {
            logger.info("TPSConfigurator: Registering TPS to CA: " + caURI);
            registerUser(secdomainURI, caURI, "ca");

        } catch (Exception e) {
            String message = "Unable to register TPS to CA: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        try {
            logger.info("TPSConfigurator: Registering TPS to TKS: " + tksURI);
            registerUser(secdomainURI, tksURI, "tks");

        } catch (Exception e) {
            String message = "Unable to register TPS to TKS: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (request.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {

            try {
                logger.info("TPSConfigurator: Registering TPS to KRA: " + kraURI);
                registerUser(secdomainURI, kraURI, "kra");

            } catch (Exception e) {
                String message = "Unable to register TPS to KRA: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }

            String transportCert;
            try {
                logger.info("TPSConfigurator: Retrieving transport cert from KRA");
                transportCert = getTransportCert(secdomainURI, kraURI);

            } catch (Exception e) {
                String message = "Unable to retrieve transport cert from KRA: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }

            try {
                logger.info("TPSConfigurator: Importing transport cert into TKS");
                exportTransportCert(secdomainURI, tksURI, transportCert);

            } catch (Exception e) {
                String message = "Unable to import transport cert into TKS: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }
        }

        try {
            String doImportStr = request.getImportSharedSecret();
            logger.debug("TPSConfigurator: importSharedSecret:" + doImportStr);

            boolean doImport = false;
            if ("true".equalsIgnoreCase(doImportStr)) {
                doImport = true;
            }

            logger.info("TPSConfigurator: Generating shared secret in TKS");
            getSharedSecret(
                    tksURI.getHost(),
                    tksURI.getPort(),
                    doImport);

        } catch (Exception e) {
            String message = "Unable to generate shared secret in TKS: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        super.finalizeConfiguration(request);
    }

    public String getTransportCert(URI secdomainURI, URI kraUri) throws Exception {

        logger.debug("TPSConfigurator: getTransportCert() start");

        CMSEngine engine = CMS.getCMSEngine();
        String sessionId = engine.getConfigSDSessionId();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");

        String c = post(
                kraUri.getHost(),
                kraUri.getPort(),
                true,
                "/kra/admin/kra/getTransportCert",
                content, null, null);

        if (c == null) {
            return null;
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);
        String status = parser.getValue("Status");

        if (!status.equals(SUCCESS)) {
            return null;
        }

        return parser.getValue("TransportCert");
    }
}
