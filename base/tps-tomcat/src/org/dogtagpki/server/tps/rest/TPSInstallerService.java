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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;

/**
 * @author alee
 *
 */
public class TPSInstallerService extends SystemConfigService  {

    public TPSInstallerService() throws EBaseException {
    }

    @Override
    public void configureSubsystem(ConfigurationRequest request,
            Collection<String> certList, String token, String domainXML) {

        super.configureSubsystem(request, certList, token, domainXML);

        // get subsystem certificate nickname
        String subsystemNick = null;
        for (SystemCertData cdata : request.getSystemCerts()) {
            if (cdata.getTag().equals("subsystem")) {
                subsystemNick = cdata.getNickname();
                break;
            }
        }

        if (subsystemNick == null || subsystemNick.isEmpty()) {
            throw new BadRequestException("No nickname provided for subsystem certificate");
        }

        // CA Info Panel
        configureTPStoCAConnector(request, subsystemNick);

        // TKS Info Panel
        configureTPStoTKSConnector(request, subsystemNick);

        //DRM Info Panel
        configureTPStoKRAConnector(request, subsystemNick);

        //AuthDBPanel
        ConfigurationUtils.updateAuthdbInfo(request.getAuthdbBaseDN(),
                request.getAuthdbHost(), request.getAuthdbPort(),
                request.getAuthdbSecureConn());
    }

    public void configureTPStoCAConnector(ConfigurationRequest data, String subsystemNick) {
        URI caUri = null;
        try {
            caUri = new URI(data.getCaUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid caURI " + caUri);
        }
        ConfigurationUtils.updateCAConnInfo(caUri, subsystemNick);
    }

    public void configureTPStoTKSConnector(ConfigurationRequest data, String subsystemNick) {
        URI tksUri = null;
        try {
            tksUri = new URI(data.getTksUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid tksURI " + tksUri);
        }

        ConfigurationUtils.updateTKSConnInfo(tksUri, subsystemNick);
    }

    public void configureTPStoKRAConnector(ConfigurationRequest data, String subsystemNick) {
        URI kraUri = null;
        try {
            kraUri = new URI(data.getCaUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid kraURI " + kraUri);
        }
        boolean keyGen = data.getEnableServerSideKeyGen().equalsIgnoreCase("true");
        ConfigurationUtils.updateKRAConnInfo(keyGen, kraUri, subsystemNick);
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
            URI caURI = new URI(request.getCaUri());
            ConfigurationUtils.registerUser(secdomainURI, caURI, "ca");

            // register TPS with TKS
            URI tksURI = new URI(request.getTksUri());
            ConfigurationUtils.registerUser(secdomainURI, tksURI, "tks");

            if (request.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                URI kraURI = new URI(request.getKraUri());
                ConfigurationUtils.registerUser(secdomainURI, kraURI, "kra");
                String transportCert = ConfigurationUtils.getTransportCert(secdomainURI, kraURI);
                ConfigurationUtils.exportTransportCert(secdomainURI, tksURI, transportCert);
            }

            // generate shared secret from the tks
            ConfigurationUtils.getSharedSecret(
                    tksURI.getHost(),
                    tksURI.getPort(),
                    Boolean.getBoolean(request.getImportSharedSecret()));

        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid URI for CA, TKS or KRA");

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in registering TPS to CA, TKS or KRA: " + e);
        }
    }
}
