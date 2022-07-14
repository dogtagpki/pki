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

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityResource;
import com.netscape.certsrv.client.ClientConfig;
import com.netscape.certsrv.client.PKIClient;

/**
 * EST backend that acts as RA for a Dogtag CA subsystem
 *
 * @author Fraser Tweedale
 */
public class DogtagRABackend extends ESTBackend {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DogtagRABackend.class);

    private ClientConfig clientConfig = new ClientConfig();

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
    }

    @Override
    public CertificateChain cacerts(Optional<String> label) throws Throwable {
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
        }
    }

    @Override
    public ESTEnrollResult simpleenroll(Optional<String> label, PKCS10 csr) {
        return ESTEnrollResult.failure(new ServiceUnavailableException("not implemented"));
    }

    @Override
    public ESTEnrollResult simplereenroll(Optional<String> label, PKCS10 csr) {
        return ESTEnrollResult.failure(new ServiceUnavailableException("not implemented)"));
    }

}
