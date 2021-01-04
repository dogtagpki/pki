//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package org.dogtagpki.ca;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

import javax.ws.rs.core.Response;

import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * @author Endi S. Dewata
 */
public class CASystemCertClient extends Client {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CASystemCertClient.class);

    public CASystemCertResource resource;

    public CASystemCertClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "systemcert");
        init();
    }

    public void init() throws Exception {
        resource = createProxy(CASystemCertResource.class);
    }

    public CertData getSigningCert() throws Exception {

        CertData certData = null;

        try {
            logger.info("Gettting CA signing certificate chain through REST service");

            Response response = resource.getSigningCert();
            certData = client.getEntity(response, CertData.class);

        } catch (PKIException e) {
            if (e.getCode() != Response.Status.NOT_FOUND.getStatusCode()) {
                throw e;
            }
            logger.warn("Unable to get CA signing certificate: " + e.getMessage());
        }

        if (certData == null || certData.getPkcs7CertChain() == null) {
            logger.info("Gettting CA signing certificate chain through legacy servlet");

            CAClient caClient = new CAClient(client);
            PKCS7 pkcs7 = caClient.getCertChain();
            certData = CertData.fromCertChain(pkcs7);
        }

        return certData;
    }

    public CertData getSubsystemCert() throws Exception {

        String c = client.get("/ca/admin/ca/getSubsystemCert", String.class);

        if (c == null) {
            throw new Exception("Unable to get subsystem certificate: No response");
        }

        ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
        XMLObject parser = new XMLObject(bis);
        String status = parser.getValue("Status");

        if ("2".equals(status)) {
            throw new Exception("Unable to get subsystem certificate: Authentication error");

        } else if (!"0".equals(status)) {
            throw new Exception("Unable to get subsystem certificate: Internal server error");
        }

        String b64 = parser.getValue("Cert");
        X509CertImpl cert = new X509CertImpl(Utils.base64decode(b64));

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                new X509Certificate[] { cert },
                new SignerInfo[0]);

        return CertData.fromCertChain(pkcs7);
    }

    public CertData getTransportCert() throws Exception {
        Response response = resource.getTransportCert();
        return client.getEntity(response, CertData.class);
    }
}
