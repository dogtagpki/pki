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
package org.dogtagpki.server.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.Collection;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;

import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.DatabaseSetupRequest;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.xml.XMLObject;
import com.netscape.ocsp.OCSPAuthority;

public class OCSPConfigurator extends Configurator {

    public OCSPConfigurator(CMSEngine engine) {
        super(engine);
    }

    private static final int DEF_REFRESH_IN_SECS_FOR_CLONE = 14400; // CRL Publishing schedule

    @Override
    public void setupDatabase(DatabaseSetupRequest request) throws Exception {

        engine.setSubsystemEnabled(OCSPAuthority.ID, true);

        super.setupDatabase(request);
    }

    @Override
    public void getDatabaseGroups(Collection<String> groups) throws Exception {
        groups.add("Trusted Managers");
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        try {
            PreOpConfig preopConfig = cs.getPreOpConfig();
            String ca_host = preopConfig.getString("ca.hostname", "");

            // import the CA certificate into the OCSP
            // configure the CRL Publishing to OCSP in CA
            if (!ca_host.equals("")) {
                engine.reinit(IOCSPAuthority.ID);

                if (!request.isClone()) {
                    importCACert();
                } else {
                    logger.debug("OCSPInstallerService: Skipping importCACertToOCSP for clone.");
                }

                if (!request.getStandAlone()) {

                    // For now don't register publishing with the CA for a clone.
                    // Preserves existing functionality
                    // Next we need to treat the publishing of clones as a group ,
                    // and fail over amongst them.
                    if (!request.isClone()) {
                        updateOCSPConfiguration(request);
                    }

                    setupClientAuthUser();
                }
            }

            if (request.isClone()) {
                configureCloneRefresh(request);
            }

        } catch (Exception e) {
            logger.error("OCSPInstallerService: " + e.getMessage(), e);
            throw new PKIException("Errors in configuring CA publishing to OCSP: " + e);
        }

        super.finalizeConfiguration(request);
    }

    public void importCACert() throws IOException, EBaseException, CertificateEncodingException {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        // get certificate chain from CA
        String b64 = preopConfig.getString("ca.pkcs7", "");
        if (b64.equals("")) {
            throw new IOException("Failed to get certificate chain");
        }

        // this could be a chain
        java.security.cert.X509Certificate[] certs = org.mozilla.jss.netscape.security.util.Cert.mapCertFromPKCS7(b64);
        if (certs == null || certs.length == 0) {
            return;
        }

        java.security.cert.X509Certificate leafCert;
        if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
            leafCert = certs[certs.length - 1];
        } else {
            leafCert = certs[0];
        }

        IOCSPAuthority ocsp = (IOCSPAuthority) engine.getSubsystem(IOCSPAuthority.ID);
        IDefStore defStore = ocsp.getDefaultStore();

        // (1) need to normalize (sort) the chain
        // (2) store certificate (and certificate chain) into
        // database
        ICRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                leafCert.getSubjectDN().getName(),
                Configurator.BIG_ZERO,
                Configurator.MINUS_ONE, null, null);

        rec.set(ICRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
        defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);

        logger.debug("OCSPConfigurator: Added CA certificate.");
    }

    public void updateOCSPConfiguration(FinalizeConfigRequest request) throws Exception {

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String caHost = preopConfig.getString("ca.hostname", "");
        int caPort = preopConfig.getInteger("ca.httpsport", -1);
        String serverURL = "https://" + caHost + ":" + caPort;

        logger.debug("OCSPConfigurator: Updating OCSP configuration in CA at " + serverURL);

        String ocspHost = engine.getAgentHost();
        int ocspPort = Integer.parseInt(engine.getAgentPort());
        String sessionId = request.getInstallToken().getToken();

        MultivaluedMap<String, String> content = new MultivaluedHashMap<String, String>();
        content.putSingle("xmlOutput", "true");
        content.putSingle("sessionID", sessionId);
        content.putSingle("ocsp_host", ocspHost);
        content.putSingle("ocsp_port", ocspPort + "");

        PKIClient client = createClient(serverURL, null, null);
        String c = client.post("/ca/ee/ca/updateOCSPConfig", content);

        if (c == null || c.equals("")) {
            logger.error("OCSPConfigurator: Unable to update OCSP configuration: No response from CA");
            throw new IOException("Unable to update OCSP configuration: No response from CA");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);

        String status = parser.getValue("Status");
        logger.debug("OCSPConfigurator: status: " + status);

        if (status.equals(Configurator.SUCCESS)) {
            logger.debug("OCSPConfigurator: Successfully updated OCSP configuration in CA");

        } else if (status.equals(Configurator.AUTH_FAILURE)) {
            logger.error("OCSPConfigurator: Unable to update OCSP configuration: Authentication failure");
            throw new EAuthException(Configurator.AUTH_FAILURE);

        } else {
            String error = parser.getValue("Error");
            logger.error("OCSPConfigurator: Unable to update OCSP configuration: " + error);
            throw new IOException(error);
        }
    }

    public void configureCloneRefresh(FinalizeConfigRequest request) {
        //Set well know default value for OCSP clone
        cs.putInteger("ocsp.store.defStore.refreshInSec", DEF_REFRESH_IN_SECS_FOR_CLONE);
    }
}
