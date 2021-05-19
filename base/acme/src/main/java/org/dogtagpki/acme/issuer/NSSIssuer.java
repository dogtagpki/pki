//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.issuer;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.dogtagpki.acme.ACMECertificate;
import org.dogtagpki.acme.database.ACMEDatabase;
import org.dogtagpki.acme.server.ACMEEngine;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PlainPasswordFile;

/**
 * @author Endi S. Dewata
 */
public class NSSIssuer extends ACMEIssuer {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSIssuer.class);

    NSSDatabase nssDatabase;
    IPasswordStore passwordStore;

    org.mozilla.jss.crypto.X509Certificate issuer;

    NSSExtensionGenerator extGenerator;
    Integer monthsValid;
    String hash;

    @Override
    public void init() throws Exception {

        logger.info("Initializing NSS issuer");

        Path instanceDir = Paths.get(System.getProperty("catalina.base"));

        String database = config.getParameter("database");
        if (database == null) database = "conf/alias";

        Path databasePath = instanceDir.resolve(database);
        logger.info("- database: " + databasePath);

        nssDatabase = new NSSDatabase(databasePath);

        String passwords = config.getParameter("passwords");
        if (passwords == null) passwords = "conf/password.conf";

        Path passwordsPath = instanceDir.resolve(passwords);
        logger.info("- passwords: " + passwordsPath);

        passwordStore = new PlainPasswordFile();
        passwordStore.init(passwordsPath.toString());
        nssDatabase.setPasswordStore(passwordStore);

        String nickname = config.getParameter("nickname");
        if (nickname == null) nickname = "ca_signing";
        logger.info("- nickname: " + nickname);

        CryptoManager cm = CryptoManager.getInstance();
        issuer = cm.findCertByNickname(nickname);

        String monthsValid = config.getParameter("monthsValid");
        if (monthsValid != null) {
            logger.info("- months valid: " + monthsValid);
            this.monthsValid = Integer.valueOf(monthsValid);
        }

        String hash = config.getParameter("hash");
        if (hash != null) {
            logger.info("- hash: " + hash);
            this.hash = hash;
        }

        String extensions = config.getParameter("extensions");
        if (extensions == null) extensions = "/usr/share/pki/acme/issuer/nss/sslserver.conf";
        logger.info("- extensions: " + extensions);

        Path extPath = instanceDir.resolve(extensions);
        extGenerator = new NSSExtensionGenerator();
        extGenerator.init(extPath.toString());
    }

    @Override
    public String issueCertificate(PKCS10 pkcs10) throws Exception {

        logger.info("Issuing certificate");
        Date currentTime = new Date();

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase acmeDatabase = engine.getDatabase();

        Extensions extensions = null;
        if (extGenerator != null) {
            extensions = extGenerator.createExtensions(issuer, pkcs10);
        }

        X509Certificate cert = nssDatabase.createCertificate(
                issuer,
                pkcs10,
                monthsValid,
                hash,
                extensions);

        BigInteger serialNumber = cert.getSerialNumber();
        String certID = Base64.encodeBase64URLSafeString(serialNumber.toByteArray());

        ACMECertificate certificate = new ACMECertificate();
        certificate.setID(certID);
        certificate.setCreationTime(currentTime);
        certificate.setData(cert.getEncoded());

        Date expirationTime = engine.getPolicy().getCertificateExpirationTime(cert.getNotAfter());
        certificate.setExpirationTime(expirationTime);

        acmeDatabase.addCertificate(certID, certificate);

        return certID;
    }

    public X509Certificate[] getCACertificateChain() throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        org.mozilla.jss.crypto.X509Certificate[] caCertChain = cm.buildCertificateChain(issuer);

        X509Certificate[] caCertChainImpl = new X509Certificate[caCertChain.length];
        for (int i = 0; i < caCertChain.length; i++) {
            org.mozilla.jss.crypto.X509Certificate cert = caCertChain[i];
            caCertChainImpl[i] = new X509CertImpl(cert.getEncoded());
        }

        return caCertChainImpl;
    }

    @Override
    public String getCertificateChain(String certID) throws Exception {

        logger.info("Retrieving certificate");

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase acmeDatabase = engine.getDatabase();

        ACMECertificate certificate = acmeDatabase.getCertificate(certID);
        X509Certificate cert = new X509CertImpl(certificate.getData());
        X509Certificate[] certChain = getCACertificateChain();

        StringWriter sw = new StringWriter();

        try (PrintWriter out = new PrintWriter(sw, true)) {

            out.println(Cert.HEADER);
            out.print(Utils.base64encodeMultiLine(cert.getEncoded()));
            out.println(Cert.FOOTER);

            for (X509Certificate caCert : certChain) {
                out.println(Cert.HEADER);
                out.print(Utils.base64encodeMultiLine(caCert.getEncoded()));
                out.println(Cert.FOOTER);
            }
        }

        return sw.toString();
    }
}
