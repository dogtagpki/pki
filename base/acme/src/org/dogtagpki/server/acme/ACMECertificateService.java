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
package org.dogtagpki.server.acme;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;

import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.codec.binary.Base64;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.cmsutil.crypto.CryptoUtil;

@Path("cert/{id}")
public class ACMECertificateService {

    ACMEConfiguration acmeConfig;

    @Context
    UriInfo uriInfo;

    public ACMEConfiguration getACMEConfig() {
        return acmeConfig;
    }

    public void setACMEConfig(ACMEConfiguration config) {
        this.acmeConfig = config;
    }

    @GET
    @Produces("application/pem-certificate-chain")
    public Response handleGET(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    @POST
    @Produces("application/pem-certificate-chain")
    public Response handlePOST(@PathParam("id") String certID) throws Exception {
        return getCertificate(certID);
    }

    public Response getCertificate(String certID) throws Exception {

        CertId id = new CertId(new BigInteger(1, Base64.decodeBase64(certID)));
        System.out.println("Retrieving certificate " + id.toHexString());

        String serverURL = acmeConfig.getServerURL();
        System.out.println(" - server URL: " + serverURL);

        String profileID = acmeConfig.getProfileID();
        System.out.println(" - profile ID: " + profileID);

        String nickname = acmeConfig.getNickname();
        System.out.println(" - nickname: " + nickname);

        String username = acmeConfig.getUsername();
        System.out.println(" - username: " + username);

        String password = acmeConfig.getPassword();

        ClientConfig clientConfig = new ClientConfig();
        clientConfig.setServerURL(serverURL);
        clientConfig.setCertNickname(nickname);
        //clientConfig.setUsername(username);
        //clientConfig.setPassword(password);

        PKIClient pkiClient = new PKIClient(clientConfig);
        CAClient caClient = new CAClient(pkiClient);
        CACertClient certClient = new CACertClient(caClient);

        CertData certData = certClient.getCert(id);

        String certChain = certData.getPkcs7CertChain();
        System.out.println("Cert chain: " + certChain);

        PKCS7 pkcs7 = new PKCS7(Utils.base64decode(certChain));
        X509Certificate[] certs = pkcs7.getCertificates();

        if (certs == null || certs.length == 0) {
            throw new Error("PKCS #7 data contains no certificates");
        }

        // sort certs from leaf to root
        certs = CryptoUtil.sortCertificateChain(certs, true);

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            for (X509Certificate cert : certs) {
                out.println(Cert.HEADER);
                out.print(Utils.base64encode(cert.getEncoded(), true));
                out.println(Cert.FOOTER);
            }
        }

        ResponseBuilder builder = Response.ok();

        builder.header("Replay-Nonce", "MYAuvOpaoIiywTezizk5vw");

        URI link = uriInfo.getBaseUriBuilder().path("directory").build();
        builder.link(link, "index");

        builder.entity(sw.toString());

        return builder.build();
    }
}
