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
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

/**
 * This class implements an OCSP utility.
 *
 * @version $Revision$, $Date$
 */
public class OCSPProcessor {

    public boolean verbose;

    public OCSPProcessor() {
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isVerbose() {
        return verbose;
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

        X500Name issuerName = (X500Name)cert.getSubjectDN();
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

    public OCSPResponse submitRequest(String url, OCSPRequest request) throws Exception {

        if (verbose) System.out.println("URL: " + url);

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            request.encode(os);
            byte[] requestData = os.toByteArray();

            if (verbose) {
                System.out.println("Data Length: " + requestData.length);
                System.out.println("Data: " + Utils.base64encode(requestData));
            }

            ByteArrayEntity requestEntity = new ByteArrayEntity(requestData);
            requestEntity.setContentType(ContentType.APPLICATION_OCTET_STREAM.getMimeType());

            HttpPost httpPost = new HttpPost(url);
            httpPost.setEntity(requestEntity);

            HttpResponse response = httpClient.execute(httpPost);
            HttpEntity responseEntity = response.getEntity();

            try (InputStream is = responseEntity.getContent()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();

                int b;
                while ((b = is.read()) != -1) {
                    buffer.write(b);
                }

                // construct OCSP response
                return (OCSPResponse)OCSPResponse.getTemplate().decode(
                        new ByteArrayInputStream(buffer.toByteArray()));

            } finally {
                EntityUtils.consume(responseEntity);
            }
        }
    }
}
