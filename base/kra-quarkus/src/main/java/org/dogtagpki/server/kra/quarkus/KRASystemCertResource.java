//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.cert.CertData;
import com.netscape.kra.KeyRecoveryAuthority;
import com.netscape.kra.TransportKeyUnit;

/**
 * JAX-RS resource for KRA system certificates.
 * Replaces KRASystemCertServlet.
 */
@Path("v2/config/cert")
public class KRASystemCertResource {

    private static final Logger logger = LoggerFactory.getLogger(KRASystemCertResource.class);
    private static final long DEFAULT_LONG_CACHE_LIFETIME = 86400;

    @Inject
    KRAEngineQuarkus engineQuarkus;

    @Context
    HttpHeaders httpHeaders;

    @GET
    @Path("transport")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTransportCert() throws Exception {
        logger.debug("KRASystemCertResource.getTransportCert()");

        KeyRecoveryAuthority kra = (KeyRecoveryAuthority)
                engineQuarkus.getEngine().getSubsystem(KeyRecoveryAuthority.ID);
        TransportKeyUnit transportUnit = kra.getTransportKeyUnit();

        X509Certificate[] chain = transportUnit.getChain();
        X509CertImpl[] chainImpl = new X509CertImpl[chain.length];

        for (int i = 0; i < chain.length; i++) {
            X509Certificate c = chain[i];
            chainImpl[i] = new X509CertImpl(c.getEncoded());
        }

        PKCS7 pkcs7 = new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                chainImpl,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);

        String reqETag = httpHeaders.getHeaderString("If-None-Match");
        String eTag = Integer.toString(certData.hashCode());

        if (reqETag != null &&
                (reqETag.equals(eTag) || reqETag.equals("\"" + eTag + "\""))) {
            return Response.notModified()
                    .header("ETag", "\"" + eTag + "\"")
                    .header("Cache-control", "no-transform, max-age=" + DEFAULT_LONG_CACHE_LIFETIME)
                    .build();
        }

        return Response.ok(certData.toJSON())
                .header("ETag", "\"" + eTag + "\"")
                .header("Cache-control", "no-transform, max-age=" + DEFAULT_LONG_CACHE_LIFETIME)
                .build();
    }
}
