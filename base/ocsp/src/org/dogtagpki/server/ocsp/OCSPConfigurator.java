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

import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.crldb.ICRLIssuingPointRecord;
import com.netscape.certsrv.ocsp.IDefStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;

public class OCSPConfigurator extends Configurator {

    public OCSPConfigurator(CMSEngine engine) {
        super(engine);
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
                }
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

        String ocspHost = cs.getHostname();
        String ocspPort = engine.getAgentPort();
        URL url = new URL("https://" + ocspHost + ":" + ocspPort);
        String sessionId = request.getInstallToken().getToken();

        PKIClient client = createClient(serverURL, null, null);
        CAClient caClient = new CAClient(client);
        caClient.addOCSPPublisher(url, sessionId);
    }
}
