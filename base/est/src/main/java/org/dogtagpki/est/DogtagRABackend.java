package org.dogtagpki.est;

import java.io.File;
import java.io.FileReader;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.Properties;

import javax.ws.rs.ServiceUnavailableException;

import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertData;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfo;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.cert.CertReviewResponse;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;

/**
 * EST backend that acts as RA for a Dogtag CA subsystem
 *
 * @author Fraser Tweedale
 */
public class DogtagRABackend extends ESTBackend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DogtagRABackend.class);

    private ClientConfig clientConfig = new ClientConfig();

    private String profile;

    @Override
    public void start() throws Throwable {
        logger.info("Initializing Dogtag RA backend");

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
            password = props.getProperty("password");
            if (password == null) {
                throw new RuntimeException(
                    "DogtagRABackend: 'password' property not present in file "
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

        // Read profile id.  This may be a temporary behaviour.  Eventually,
        // the EST request authorization interface should output the enrollment
        // profile to be used.
        profile = config.getParameter("profile");
        if (profile == null) {
            throw new RuntimeException("DogtagRABackend: 'password' property missing");
        }
    }

    @Override
    public CertificateChain cacerts(Optional<String> label) throws PKIException {
        try (PKIClient pkiClient = new PKIClient(clientConfig)) {
            AuthorityClient authorityClient = new AuthorityClient(pkiClient, "ca");

            String authorityID = label.orElse(AuthorityResource.HOST_AUTHORITY);
            String pkcs7pem = authorityClient.getChainPEM(authorityID);
            logger.debug("Cert chain:\n" + pkcs7pem);

            PKCS7 pkcs7 = new PKCS7(pkcs7pem);
            X509Certificate[] certs = pkcs7.getCertificates();
            if (certs == null || certs.length == 0) {
                return null;  // will result in 404
            }
            return new CertificateChain(certs);
        } catch (PKIException e) {
            throw e; // re-raise
        } catch (Throwable e) {
            // unexpected; wrap in PKIException, which will result in 500
            throw new PKIException("Internal error in /cacerts: " + e, e);
        }
    }

    @Override
    public X509CertImpl simpleenroll(Optional<String> label, PKCS10 csr) throws PKIException {
        return issueCertificate(label, csr);
    }

    @Override
    public X509CertImpl simplereenroll(Optional<String> label, PKCS10 csr) throws PKIException {
        /* At the moment, simplereenroll does the same thing as simpleenroll.
         * These are separate methods in case some backends need different or
         * additional behaviour for re-enroll (e.g. revoking previous certificates).
         */
        return simpleenroll(label, csr);
    }

    private X509CertImpl issueCertificate(Optional<String> label, PKCS10 pkcs10)
            throws PKIException {
        logger.info("Issuing certificate");

        // interpret label as authority-id
        AuthorityID aid = null;
        if (label.isPresent()) {
            try {
                aid = new AuthorityID(label.get());
            } catch (Throwable e) {
                throw new BadRequestException("Bad AuthorityID: " + label.get(), e);
            }
        }

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
            CertRequestInfos infos = certClient.enrollRequest(certEnrollmentRequest, aid, null);

            logger.info("Responses:");
            CertRequestInfo info = infos.getEntries().iterator().next();

            RequestId requestId = info.getRequestId();
            logger.info("- Request ID: " + requestId.toHexString());
            logger.info("  Type: " + info.getRequestType());
            logger.info("  Request Status: " + info.getRequestStatus());
            logger.info("  Operation Result: " + info.getOperationResult());

            String error = info.getErrorMessage();
            if (error != null) {
                throw new PKIException("Unable to generate certificate: " + error);
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
            CertData certData = certClient.getCert(id);
            String certPem = certData.getEncoded();
            return Cert.mapCert(certPem);
        } catch (PKIException e) {
            throw e; // re-raise
        } catch (Throwable e) {
            // unexpected; wrap in PKIException, which will result in 500
            throw new PKIException("Internal error in /cacerts: " + e, e);
        }
    }

}
