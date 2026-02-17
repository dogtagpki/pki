//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cms.servlet.admin.KRAConnectorProcessor;

/**
 * JAX-RS resource for CA system certificate operations.
 * Replaces CASystemCertServlet.
 */
@Path("v2/config/cert")
public class CASystemCertResource {

    private static final Logger logger = LoggerFactory.getLogger(CASystemCertResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Path("signing")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getSigningCert() throws Exception {
        CAEngine engine = engineQuarkus.getEngine();
        CertificateAuthority ca = engine.getCA();
        CASigningUnit su = ca.getSigningUnit();

        X509Certificate signingCert = su.getCert();
        X509CertImpl cert = new X509CertImpl(signingCert.getEncoded());
        java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

        PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certChain,
                new SignerInfo[0]);

        CertData certData = CertData.fromCertChain(pkcs7);
        return Response.ok(certData.toJSON())
                .header("Cache-control", "no-transform, max-age=86400")
                .build();
    }

    @GET
    @Path("transport")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getTransportCert() throws Exception {
        CAEngine engine = engineQuarkus.getEngine();

        try {
            KRAConnectorProcessor processor = new KRAConnectorProcessor(java.util.Locale.getDefault());
            processor.setCMSEngine(engine);
            processor.init();

            KRAConnectorInfo info = processor.getConnectorInfo();
            String encodedCert = info.getTransportCert();
            byte[] bytes = Utils.base64decode(encodedCert);
            X509CertImpl cert = new X509CertImpl(bytes);
            java.security.cert.X509Certificate[] certChain = engine.getCertChain(cert);

            PKCS7 pkcs7 = new PKCS7(new AlgorithmId[0],
                    new ContentInfo(new byte[0]),
                    certChain,
                    new SignerInfo[0]);

            CertData certData = CertData.fromCertChain(pkcs7);
            return Response.ok(certData.toJSON())
                    .header("Cache-control", "no-transform, max-age=86400")
                    .build();

        } catch (EBaseException e) {
            throw new PKIException("Unable to get transport cert: " + e.getMessage(), e);
        }
    }
}
