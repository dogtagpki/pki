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

package org.dogtagpki.server.rest;

import java.net.URI;
import java.security.Principal;

import javax.ws.rs.core.Response;

import org.jboss.resteasy.plugins.providers.atom.Link;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.certsrv.system.SystemCertResource;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;

/**
 * This is the class used to list, retrieve and modify system certificates for all Java subsystems.
 *
 * @author alee
 *
 */
public class SystemCertService extends PKIService implements SystemCertResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SystemCertService.class);

    /**
     * Used to retrieve the transport certificate
     */
    public Response getTransportCert() {

        CMSEngine engine = CMS.getCMSEngine();
        try {
            EngineConfig cs = engine.getConfig();
            String type = cs.getType();

            CertData certData;
            if ("CA".equals(type)) {
                certData = getTransportCertFromCA();

            } else if ("KRA".equals(type)) {
                certData = getTransportCertFromKRA();

            } else {
                throw new ResourceNotFoundException("Transport certificate not available in " + type);
            }

            URI uri = uriInfo.getRequestUri();
            certData.setLink(new Link("self", uri));

            return sendConditionalGetResponse(DEFAULT_LONG_CACHE_LIFETIME, certData, request);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            logger.error("SystemCertService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    public CertData getTransportCertFromCA() throws Exception {
        KRAConnectorProcessor processor = new KRAConnectorProcessor(getLocale(headers));
        KRAConnectorInfo info = processor.getConnectorInfo();
        String encodedCert = info.getTransportCert();

        byte[] bytes = Utils.base64decode(encodedCert);
        X509CertImpl cert = new X509CertImpl(bytes);

        return createCertificateData(cert);
    }

    public CertData getTransportCertFromKRA() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();
        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) engine.getSubsystem(IKeyRecoveryAuthority.ID);
        if (kra == null) {
            // no KRA
            throw new ResourceNotFoundException("KRA subsystem not found.");
        }

        ITransportKeyUnit tu = kra.getTransportKeyUnit();
        if (tu == null) {
            logger.error("getTransportCert: transport key unit is null");
            throw new PKIException("No transport key unit.");
        }

        X509Certificate transportCert = tu.getCertificate();
        if (transportCert == null) {
            logger.error("getTransportCert: transport cert is null");
            throw new PKIException("Transport cert not found.");
        }

        return createCertificateData(transportCert);
    }

    public CertData createCertificateData(X509CertImpl cert) throws Exception {

        CertData data = new CertData();

        data.setSerialNumber(new CertId(cert.getSerialNumber()));

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) data.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) data.setSubjectDN(subjectDN.toString());

        String b64 = Cert.HEADER + "\n" + Utils.base64encode(cert.getEncoded(), true) + Cert.FOOTER;
        data.setEncoded(b64);

        return data;
    }

    public CertData createCertificateData(X509Certificate cert) throws Exception {

        CertData data = new CertData();

        data.setSerialNumber(new CertId(cert.getSerialNumber()));

        Principal issuerDN = cert.getIssuerDN();
        if (issuerDN != null) data.setIssuerDN(issuerDN.toString());

        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN != null) data.setSubjectDN(subjectDN.toString());

        String b64 = Cert.HEADER + "\n" + Utils.base64encode(cert.getEncoded(), true) + Cert.FOOTER;
        data.setEncoded(b64);

        return data;
    }
}
