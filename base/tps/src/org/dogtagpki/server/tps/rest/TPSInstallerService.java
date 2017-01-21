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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.rest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;

import org.dogtagpki.server.rest.SystemConfigService;
import org.dogtagpki.server.tps.installer.TPSInstaller;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
public class TPSInstallerService extends SystemConfigService  {


    public TPSInstallerService() throws EBaseException {
    }

    @Override
    public void configureSubsystem(ConfigurationRequest request,
            Collection<String> certList, String token, String domainXML) throws Exception {

        super.configureSubsystem(request, certList, token, domainXML);

        // get token prefix, if applicable
        String tokPrefix = "";
        if (!request.getToken().equals(CryptoUtil.INTERNAL_TOKEN_FULL_NAME) &&
                !request.getToken().equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
            tokPrefix = request.getToken() + ":";
        }

        // get subsystem certificate nickname
        String nickname = null;
        for (SystemCertData cert : request.getSystemCerts()) {
            if (cert.getTag().equals("subsystem")) {
                nickname = cert.getNickname();
                break;
            }
        }

        if (nickname == null || nickname.isEmpty()) {
            throw new BadRequestException("No nickname provided for subsystem certificate");
        }

        // CA Info Panel
        configureCAConnector(request, tokPrefix + nickname);

        // TKS Info Panel
        configureTKSConnector(request, tokPrefix + nickname);

        //DRM Info Panel
        configureKRAConnector(request, tokPrefix + nickname);

        //AuthDBPanel
        ConfigurationUtils.updateAuthdbInfo(request.getAuthdbBaseDN(),
                request.getAuthdbHost(), request.getAuthdbPort(),
                request.getAuthdbSecureConn());
    }

    public void configureCAConnector(ConfigurationRequest request, String nickname) {
        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureCAConnector(request.getCaUri(), nickname);
    }

    public void configureTKSConnector(ConfigurationRequest request, String nickname) {

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureTKSConnector(request.getTksUri(), nickname);
    }

    public void configureKRAConnector(ConfigurationRequest request, String nickname) {

        boolean keygen = request.getEnableServerSideKeyGen().equalsIgnoreCase("true");

        // TODO: get installer from session
        TPSInstaller installer = new TPSInstaller();
        installer.configureKRAConnector(keygen, request.getKraUri(), nickname);
    }

    @Override
    public void configureDatabase(ConfigurationRequest request) {

        super.configureDatabase(request);

        cs.putString("tokendb.activityBaseDN", "ou=Activities," + request.getBaseDN());
        cs.putString("tokendb.baseDN", "ou=Tokens," + request.getBaseDN());
        cs.putString("tokendb.certBaseDN", "ou=Certificates," + request.getBaseDN());
        cs.putString("tokendb.userBaseDN", request.getBaseDN());
        cs.putString("tokendb.hostport", request.getDsHost() + ":" + request.getDsPort());
    }

    @Override
    public void finalizeConfiguration(ConfigurationRequest request) {

        super.finalizeConfiguration(request);

        try {
            ConfigurationUtils.addProfilesToTPSUser(request.getAdminUID());

            URI secdomainURI = new URI(request.getSecurityDomainUri());

            // register TPS with CA
            URI caURI = request.getCaUri();
            ConfigurationUtils.registerUser(secdomainURI, caURI, "ca");

            // register TPS with TKS
            URI tksURI = request.getTksUri();
            ConfigurationUtils.registerUser(secdomainURI, tksURI, "tks");

            if (request.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                URI kraURI = request.getKraUri();
                ConfigurationUtils.registerUser(secdomainURI, kraURI, "kra");
                String transportCert = ConfigurationUtils.getTransportCert(secdomainURI, kraURI);
                ConfigurationUtils.exportTransportCert(secdomainURI, tksURI, transportCert);
            }

            String doImportStr = request.getImportSharedSecret();
            CMS.debug("finalizeConfiguration: importSharedSecret:" + doImportStr);
            // generate shared secret from the tks

            boolean doImport = false;

            if("true".equalsIgnoreCase(doImportStr)) {
                CMS.debug("finalizeConfiguration: importSharedSecret: importSharedSecret is true.");
                doImport = true;
            }

            ConfigurationUtils.getSharedSecret(
                    tksURI.getHost(),
                    tksURI.getPort(),
                    doImport);

        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid URI for CA, TKS or KRA");

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in registering TPS to CA, TKS or KRA: " + e);
        }
    }
}
