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
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import org.dogtagpki.server.tps.installer.TPSInstaller;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.AdminSetupResponse;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.xml.XMLObject;

public class TPSConfigurator extends Configurator {

    public TPSConfigurator(CMSEngine engine) {
        super(engine);
    }

    public void configureCAConnector(URI caURI, String nickname) {

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureCAConnector(caURI, nickname);
    }

    public void configureTKSConnector(URI tksURI, String nickname) {

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureTKSConnector(tksURI, nickname);
    }

    public void configureKRAConnector(URI kraURI, String nickname, boolean keygen) {

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureKRAConnector(keygen, kraURI, nickname);
    }

    @Override
    public void setupDatabase(DatabaseSetupRequest request) throws Exception {

        engine.setSubsystemEnabled(SelfTestSubsystem.ID, true);

        super.setupDatabase(request);
    }

    @Override
    public void setupAdmin(AdminSetupRequest request, AdminSetupResponse response) throws Exception {

        super.setupAdmin(request, response);

        logger.debug("Adding all profiles to TPS admin user");

        UGSubsystem system = engine.getUGSubsystem();

        String adminID = request.getAdminUID();
        IUser user = system.getUser(adminID);

        List<String> profiles = new ArrayList<String>();
        profiles.add(UserResource.ALL_PROFILES);

        user.setTpsProfiles(profiles);
        system.modifyUser(user);
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        URI secdomainURI = new URI(request.getSecurityDomainUri());
        URI caURI = request.getCaUri();
        URI tksURI = request.getTksUri();
        URI kraURI = request.getKraUri();

        boolean keygen = request.getEnableServerSideKeyGen().equalsIgnoreCase("true");

        String nickname = cs.getString("tps.subsystem.nickname");
        String tokenname = cs.getString("tps.subsystem.tokenname");

        if (!CryptoUtil.isInternalToken(tokenname)) {
            nickname = tokenname + ":" + nickname;
        }

        logger.debug("TPSConfigurator: subsystem cert: " + nickname);

        logger.info("TPSConfigurator: Configuring CA connector");
        configureCAConnector(caURI, nickname);

        logger.info("TPSConfigurator: Configuring TKS connector");
        configureTKSConnector(tksURI, nickname);

        logger.info("TPSConfigurator: Configuring KRA connector");
        configureKRAConnector(kraURI, nickname, keygen);

        try {
            logger.info("TPSConfigurator: Registering TPS to CA: " + caURI);
            registerUser(request, secdomainURI, caURI, "ca");

        } catch (Exception e) {
            String message = "Unable to register TPS to CA: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        try {
            logger.info("TPSConfigurator: Registering TPS to TKS: " + tksURI);
            registerUser(request, secdomainURI, tksURI, "tks");

        } catch (Exception e) {
            String message = "Unable to register TPS to TKS: " + e.getMessage();
            logger.error(message, e);
            throw new PKIException(message, e);
        }

        if (keygen) {

            try {
                logger.info("TPSConfigurator: Registering TPS to KRA: " + kraURI);
                registerUser(request, secdomainURI, kraURI, "kra");

            } catch (Exception e) {
                String message = "Unable to register TPS to KRA: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }

            String transportCert;
            try {
                logger.info("TPSConfigurator: Retrieving transport cert from KRA");
                transportCert = getTransportCert(request, secdomainURI, kraURI);

            } catch (Exception e) {
                String message = "Unable to retrieve transport cert from KRA: " + e.getMessage();
                logger.error(message, e);
                throw new PKIException(message, e);
            }

            try {
                logger.info("TPSConfigurator: Importing transport cert into TKS");
                exportTransportCert(request, secdomainURI, tksURI, transportCert);

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

    public String getTransportCert(FinalizeConfigRequest request, URI secdomainURI, URI kraUri) throws Exception {

        logger.debug("TPSConfigurator: getTransportCert() start");

        String sessionId = request.getInstallToken().getToken();

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

    public void exportTransportCert(
            FinalizeConfigRequest request,
            URI secdomainURI,
            URI targetURI,
            String transportCert) throws Exception {

        String sessionId = request.getInstallToken().getToken();

        String securePort = cs.getString("service.securePort", "");
        String machineName = cs.getHostname();
        String name = "transportCert-" + machineName + "-" + securePort;

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("name", name);
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("auth_hostname", secdomainURI.getHost());
        content.putSingle("auth_port", secdomainURI.getPort() + "");
        content.putSingle("certificate", transportCert);

        String targetURL = "/tks/admin/tks/importTransportCert";

        String response = post(
                targetURI.getHost(),
                targetURI.getPort(),
                true,
                targetURL,
                content, null, null);

        if (response == null || response.equals("")) {
            logger.error("TPSConfigurator: The server " + targetURI + " is not available");
            throw new IOException("The server " + targetURI + " is not available");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(response.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("TPSConfigurator: status: " + status);

        if (status.equals(AUTH_FAILURE)) {
            throw new EAuthException(AUTH_FAILURE);
        }

        if (!status.equals(SUCCESS)) {
            String error = parser.getValue("Error");
            throw new IOException(error);
        }

        logger.debug("TPSConfigurator: Successfully added transport cert to " + targetURI);
    }

    public void getSharedSecret(String tksHost, int tksPort, boolean importKey) throws Exception {

        String host = cs.getString("service.machineName");
        String port = cs.getString("service.securePort");
        String nick = "TPS-" + host + "-" + port + " sharedSecret";

        cs.putString("conn.tks1.tksSharedSymKeyName", nick);
        cs.commit(false);
    }
}
