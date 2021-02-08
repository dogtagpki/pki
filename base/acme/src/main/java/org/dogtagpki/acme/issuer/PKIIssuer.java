//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.issuer;

import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMERevocation;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.cert.CertRevokeRequest;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * @author Endi S. Dewata
 */
public class PKIIssuer extends ACMEIssuer {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIIssuer.class);

    private ClientConfig clientConfig = new ClientConfig();
    private String profile;

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public void init() throws Exception {

        logger.info("Initializing PKI issuer");

        String url = config.getParameter("url");
        logger.info("- URL: " + url);
        clientConfig.setServerURL(url);

        String nickname = config.getParameter("nickname");
        if (nickname != null) {
            logger.info("- nickname: " + nickname);
            clientConfig.setCertNickname(nickname);
        }

        String username = config.getParameter("username");
        if (username != null) {
            logger.info("- username: " + username);
            clientConfig.setUsername(username);
        }

        String password = null;
        String passwordFilename = config.getParameter("passwordFile");
        if (passwordFilename != null) {
            // read password from file
            File passwordFile = new File(passwordFilename);

            logger.info("Loading password file " + passwordFilename);
            Properties props = new Properties();
            try (FileReader reader = new FileReader(passwordFile)) {
                props.load(reader);
            }
            password = props.getProperty("acmeUserPassword");
            if (password == null) {
                throw new RuntimeException(
                    "PKIIssuer: 'acmeUserPassword' property not present in file "
                    + passwordFilename
                );
            }
        } else {
            password = config.getParameter("password");
        }

        // password might be null if we are using certificate authn;
        // we only need to set it in the client config if != null
        if (password != null) {
            clientConfig.setPassword(password);
        }

        profile = config.getParameter("profile");
        logger.info("- profile: " + profile);
    }

    public String issueCertificate(PKCS10 pkcs10) throws Exception {

        logger.info("Issuing certificate");

        try (PKIClient pkiClient = new PKIClient(clientConfig)) {

            CAClient caClient = new CAClient(pkiClient);

            // Here the agent credentials are stored in the ClientConfig and will
            // be sent to the CA automatically if any of the methods being called
            // requires REST authentication. However, the methods being called
            // depend on the cert profile being used.
            //
            // If the profile has an authenticator, the request can be completed
            // with the following methods:
            // - CACertClient.getEnrollmentTemplate()
            // - CACertClient.enrollRequest()
            //
            // The above methods do not require REST authentication, but the
            // profile still requires authentication, so the credentials must be
            // provided either through the request itself (i.e. using profile
            // authentication) or by calling CAClient.login() (i.e. using REST
            // authentication).
            //
            // If the profile does not have an authenticator, the request must
            // be reviewed and approved with the following additional methods:
            // - CACertClient.reviewRequest()
            // - CACertClient.approveRequest()
            //
            // The above methods do require REST authentication so in this case
            // it's not actually necessary to call CAClient.login(). However, to
            // support both types of profiles the CAClient.login() needs to be
            // called explicitly.
            caClient.login();

            CACertClient certClient = new CACertClient(caClient);
            CertEnrollmentRequest certEnrollmentRequest = certClient.getEnrollmentTemplate(profile);

            for (ProfileInput input : certEnrollmentRequest.getInputs()) {

                ProfileAttribute typeAttr = input.getAttribute("cert_request_type");
                if (typeAttr != null) {
                    typeAttr.setValue("pkcs10");
                }

                ProfileAttribute csrAttr = input.getAttribute("cert_request");
                if (csrAttr != null) {
                    csrAttr.setValue(Utils.base64encodeSingleLine(pkcs10.toByteArray()));
                }
            }

            logger.info("Request:\n" + certEnrollmentRequest);

            CertRequestInfos infos = certClient.enrollRequest(certEnrollmentRequest, null, null);

            logger.info("Responses:");
            CertRequestInfo info = infos.getEntries().iterator().next();

            RequestId requestId = info.getRequestId();

            logger.info("- Request ID: " + requestId);
            logger.info("  Type: " + info.getRequestType());
            logger.info("  Request Status: " + info.getRequestStatus());
            logger.info("  Operation Result: " + info.getOperationResult());

            String error = info.getErrorMessage();
            if (error != null) {
                throw new Exception("Unable to generate certificate: " + error);
            }

            CertId id = null;
            if (info.getRequestStatus() == RequestStatus.COMPLETE) {
                id = info.getCertId();
            } else {
                CertReviewResponse reviewInfo = certClient.reviewRequest(requestId);
                certClient.approveRequest(requestId, reviewInfo);

                info = certClient.getRequest(requestId);
                id = info.getCertId();
            }

            logger.info("Serial number: " + id.toHexString());
            BigInteger serialNumber = id.toBigInteger();
            return Base64.encodeBase64URLSafeString(serialNumber.toByteArray());
        }
    }

    public String getCertificateChain(String certID) throws Exception {

        CertId id = new CertId(new BigInteger(1, Base64.decodeBase64(certID)));
        logger.info("Serial number: " + id.toHexString());

        try (PKIClient pkiClient = new PKIClient(clientConfig)) {

            CAClient caClient = new CAClient(pkiClient);
            CACertClient certClient = new CACertClient(caClient);
            CertData certData = certClient.getCert(id);

            String pkcs7Chain = certData.getPkcs7CertChain();
            logger.info("Cert chain:\n" + pkcs7Chain);

            PKCS7 pkcs7 = new PKCS7(Utils.base64decode(pkcs7Chain));
            X509Certificate[] certs = pkcs7.getCertificates();

            if (certs == null || certs.length == 0) {
                throw new Error("PKCS #7 data contains no certificates");
            }

            // sort certs from leaf to root
            certs = Cert.sortCertificateChain(certs, true);

            StringWriter sw = new StringWriter();

            try (PrintWriter out = new PrintWriter(sw, true)) {
                for (X509Certificate cert : certs) {
                    out.println(Cert.HEADER);
                    out.print(Utils.base64encode(cert.getEncoded(), true));
                    out.println(Cert.FOOTER);
                }
            }

            return sw.toString();
        }
    }

    public void revokeCertificate(ACMERevocation revocation) throws Exception {

        String certBase64 = revocation.getCertificate();
        byte[] certBytes = Utils.base64decode(certBase64);
        Integer reason = revocation.getReason();

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {
            out.println(Cert.HEADER);
            out.print(Utils.base64encode(certBytes, true));
            out.println(Cert.FOOTER);
        }

        String certPEM = sw.toString();

        logger.info("Certificate:\n" + certPEM);
        logger.info("Reason: " + reason);

        X509CertImpl certImpl = new X509CertImpl(certBytes);
        CertId certID = new CertId(certImpl.getSerialNumber());
        logger.info("Serial number: " + certID.toHexString());

        logger.info("Reviewing certificate");

        try (PKIClient pkiClient = new PKIClient(clientConfig)) {

            CAClient caClient = new CAClient(pkiClient);
            CACertClient certClient = new CACertClient(caClient);
            CertData certData = certClient.reviewCert(certID);

            // Compare cert in request to cert retrieved from PKI.
            // This prevents DOS attacks against certificates from this issuer,
            // where the presented certificate was from a different issuer or
            // has been modified (we don't validate it cryptographically).
            //
            String certFromIssuerPEM = certData.getEncoded();
            if (null == certFromIssuerPEM) {
                throw new Exception(
                    "Unable to revoke certificate: failed to retrieve cert from PKI");
            }
            byte[] certFromIssuerDER = Cert.parseCertificate(certFromIssuerPEM);
            if (!Arrays.equals(certBytes, certFromIssuerDER)) {
                throw new Exception(
                    "Unable to revoke certificate: cert in request was not issued by this PKI");
                // TODO better exception (400?)
            }

            CertRevokeRequest request = new CertRevokeRequest();
            request.setReason(RevocationReason.valueOf(reason));
            request.setNonce(certData.getNonce());

            logger.info("Revoking certificate");
            CertRequestInfo certRequestInfo = certClient.revokeCert(certID, request);

            RequestStatus status = certRequestInfo.getRequestStatus();
            if (status != RequestStatus.COMPLETE) {
                throw new Exception("Unable to revoke certificate: " + status);
            }

            if (certRequestInfo.getOperationResult().equals(CertRequestInfo.RES_ERROR)) {
                String error = certRequestInfo.getErrorMessage();
                throw new Exception("Unable to revoke certificate: " + error);
            }
        }
    }
}
