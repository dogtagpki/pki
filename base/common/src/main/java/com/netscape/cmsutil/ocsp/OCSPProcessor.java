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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmsutil.ocsp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

/**
 * This class implements an OCSP utility.
 *
 * @version $Revision$, $Date$
 */
public class OCSPProcessor {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(OCSPProcessor.class);

    public String url;

    public OCSPProcessor() {
    }

    public String getURL() {
        return url;
    }

    public void setURL(String url) {
        this.url = url;
    }

    /**
     * Create OCSP request from binary data.
     */
    public OCSPRequest createRequest(byte[] data) throws Exception {
        OCSPRequest.Template template = new OCSPRequest.Template();
        return (OCSPRequest)template.decode(new ByteArrayInputStream(data));
    }

    /**
     * Create OCSP request from nickname of CA certificate and serial number
     * of certificate to be checked.
     */
    public OCSPRequest createRequest(String caNickname, BigInteger serialNumber)
             throws Exception {

        CryptoManager manager = CryptoManager.getInstance();
        X509Certificate caCert = manager.findCertByNickname(caNickname);
        X509CertImpl cert = new X509CertImpl(caCert.getEncoded());

        X500Name issuerName = cert.getSubjectName();
        X509Key issuerKey = (X509Key)cert.getPublicKey();

        return createRequest(issuerName, issuerKey, serialNumber);
    }

    /**
     * Create OCSP request from issuer name, issuer public key, and serial number
     * of certificate to be checked.
     */
    public OCSPRequest createRequest(X500Name issuerName, X509Key issuerKey, BigInteger serialNumber)
            throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA");

        // calculate hashes
        byte issuerNameHash[] = md.digest(issuerName.getEncoded());
        byte issuerKeyHash[] = md.digest(issuerKey.getKey());

        // constructing the OCSP request
        CertID certID = new CertID(
                new AlgorithmIdentifier(
                        new OBJECT_IDENTIFIER("1.3.14.3.2.26"), new NULL()),
                new OCTET_STRING(issuerNameHash),
                new OCTET_STRING(issuerKeyHash),
                new INTEGER(serialNumber));

        Request request = new Request(certID, null);

        SEQUENCE requestList = new SEQUENCE();
        requestList.addElement(request);

        TBSRequest tbsRequest = new TBSRequest(null, null, requestList, null);

        return new OCSPRequest(tbsRequest, null);
    }

    public OCSPResponse submitRequest(OCSPRequest request) throws Exception {
        return submitRequest(url, request);
    }

    public OCSPResponse submitRequest(String url, OCSPRequest request) throws Exception {

        logger.info("URL: " + url);

        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            request.encode(os);
            byte[] requestData = os.toByteArray();

            logger.info("Request Length: " + requestData.length);
            logger.info("Request:\n" + Utils.base64encode(requestData, true));

            ByteArrayEntity requestEntity = new ByteArrayEntity(requestData);
            requestEntity.setContentType(ContentType.APPLICATION_OCTET_STREAM.getMimeType());

            HttpPost httpPost = new HttpPost(url);
            httpPost.setEntity(requestEntity);

            HttpResponse response = client.execute(httpPost);
            HttpEntity responseEntity = response.getEntity();

            try (InputStream is = responseEntity.getContent()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();

                int b;
                while ((b = is.read()) != -1) {
                    buffer.write(b);
                }

                // construct OCSP response

                byte[] responseData = buffer.toByteArray();

                logger.info("Response Length: " + responseData.length);
                logger.info("Response:\n" + Utils.base64encode(responseData, true));

                return (OCSPResponse)OCSPResponse.getTemplate().decode(
                        new ByteArrayInputStream(responseData));

            } finally {
                EntityUtils.consume(responseEntity);
            }
        }
    }
}
