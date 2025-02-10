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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.client;

import java.io.Console;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.ca.CASystemCertClient;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.common.CAInfoClient;
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.cert.CertEnrollmentRequest;
import com.netscape.certsrv.cert.CertRequestInfos;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.profile.ProfileAttribute;
import com.netscape.certsrv.profile.ProfileInput;
import com.netscape.cmstools.ca.CACertRequestCLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.ldap.util.DN;
import netscape.ldap.util.RDN;

/**
 * @author Endi S. Dewata
 */
public class ClientCertRequestCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClientCertRequestCLI.class);

    public ClientCLI clientCLI;

    public ClientCertRequestCLI(ClientCLI clientCLI) {
        super("cert-request", "Request a certificate", clientCLI);
        this.clientCLI = clientCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [Subject DN] [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "type", true, "Request type (default: pkcs10)");
        option.setArgName("request type");
        options.addOption(option);

        option = new Option(null, "username", true, "Username for request authentication");
        option.setArgName("username");
        options.addOption(option);

        option = new Option(null, "password", false, "Prompt password for request authentication");
        options.addOption(option);

        option = new Option(null, "attribute-encoding", false, "Enable Attribute encoding");
        options.addOption(option);

        option = new Option(null, "algorithm", true, "Algorithm (default: rsa)");
        option.setArgName("algorithm name");
        options.addOption(option);

        option = new Option(null, "length", true, "RSA key length (default: 2048)");
        option.setArgName("key length");
        options.addOption(option);

        option = new Option(null, "wrap", false, "Generate RSA key for wrapping/unwrapping");
        options.addOption(option);

        option = new Option(null, "oaep", false, "Use OAEP key wrap algorithm.");
        options.addOption(option);

        option = new Option(null, "curve", true, "ECC key curve name (default: nistp256)");
        option.setArgName("curve name");
        options.addOption(option);

        option = new Option(null, "ssl-ecdh", false, "SSL certificate with ECDH ECDSA");
        options.addOption(option);

        option = new Option(null, "permanent", false, "Permanent");
        options.addOption(option);

        option = new Option(null, "sensitive", true, "Sensitive");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "extractable", true, "Extractable");
        option.setArgName("boolean");
        options.addOption(option);

        option = new Option(null, "transport", true, "PEM transport certificate");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "profile", true,
                "Certificate profile (RSA default: caUserCert, ECC default: caECUserCert)");
        option.setArgName("profile");
        options.addOption(option);

        option = new Option(null, "without-pop", false, "Do not include Proof-of-Possession in CRMF request");
        options.addOption(option);

        option = new Option(null, "issuer-id", true, "Authority ID (host authority if omitted)");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "issuer-dn", true, "Authority DN (host authority if omitted)");
        option.setArgName("DN");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments specified.");
        }

        String certRequestUsername = cmd.getOptionValue("username");

        String subjectDN;

        if (cmdArgs.length == 0) {
            if (certRequestUsername == null) {
                throw new Exception("Missing subject DN or request username.");
            }

            subjectDN = "UID=" + certRequestUsername;

        } else {
            subjectDN = cmdArgs[0];
        }

        // pkcs10, crmf
        String requestType = cmd.getOptionValue("type", "pkcs10");

        boolean attributeEncoding = cmd.hasOption("attribute-encoding");

        // rsa, ec
        String algorithm = cmd.getOptionValue("algorithm", "rsa");
        int length = Integer.parseInt(cmd.getOptionValue("length", "2048"));
        boolean wrap = cmd.hasOption("wrap");
        boolean useOAEP = cmd.hasOption("oaep");

        String curve = cmd.getOptionValue("curve", "nistp256");
        boolean sslECDH = cmd.hasOption("ssl-ecdh");
        boolean temporary = !cmd.hasOption("permanent");

        String s = cmd.getOptionValue("sensitive");
        int sensitive;
        if (s == null) {
            sensitive = -1;
        } else {
            if (!s.equalsIgnoreCase("true") && !s.equalsIgnoreCase("false")) {
                throw new IllegalArgumentException("Invalid sensitive parameter: " + s);
            }
            sensitive = Boolean.parseBoolean(s) ? 1 : 0;
        }

        s = cmd.getOptionValue("extractable");
        int extractable;
        if (s == null) {
            extractable = -1;
        } else {
            if (!s.equalsIgnoreCase("true") && !s.equalsIgnoreCase("false")) {
                throw new IllegalArgumentException("Invalid extractable parameter: " + s);
            }
            extractable = Boolean.parseBoolean(s) ? 1 : 0;
        }

        String transportCertFilename = cmd.getOptionValue("transport");

        String profileID = cmd.getOptionValue("profile");
        if (profileID == null) {
            if (algorithm.equals("rsa")) {
                profileID = "caUserCert";
            } else if (algorithm.equals("ec")) {
                profileID = "caECUserCert";
            }
        }

        boolean withPop = !cmd.hasOption("without-pop");

        AuthorityID aid = null;
        if (cmd.hasOption("issuer-id")) {
            String aidString = cmd.getOptionValue("issuer-id");
            try {
                aid = new AuthorityID(aidString);
            } catch (IllegalArgumentException e) {
                throw new Exception("Invalid issuer ID: " + aidString, e);
            }
        }

        X500Name adn = null;
        if (cmd.hasOption("issuer-dn")) {
            String adnString = cmd.getOptionValue("issuer-dn");
            try {
                adn = new X500Name(adnString);
            } catch (IOException e) {
                throw new Exception("Invalid issuer DN: " + adnString, e);
            }
        }

        if (aid != null && adn != null) {
            throw new Exception("--issuer-id and --issuer-dn options are mutually exclusive");
        }

        MainCLI mainCLI = (MainCLI) getRoot();
        NSSDatabase nssdb = mainCLI.getNSSDatabase();

        mainCLI.init();
        PKIClient client = getClient();

        CryptoManager manager = CryptoManager.getInstance();
        CryptoToken token = manager.getThreadToken();

        KeyPair keyPair;

        if ("rsa".equals(algorithm)) {

            keyPair = nssdb.createRSAKeyPair(
                    token,
                    length,
                    wrap);

        } else if ("ec".equals(algorithm)) {

            keyPair = nssdb.createECKeyPair(
                    token,
                    curve,
                    sslECDH,
                    temporary,
                    sensitive,
                    extractable);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        String csr;
        if ("pkcs10".equals(requestType)) {

            csr = createPKCS10Request(
                    nssdb,
                    keyPair,
                    subjectDN);

        } else if ("crmf".equals(requestType)) {

            String encoded;
            if (transportCertFilename == null) {
                CASystemCertClient certClient = new CASystemCertClient(client, "ca");
                encoded = certClient.getTransportCert().getEncoded();

            } else {
                encoded = new String(Files.readAllBytes(Paths.get(transportCertFilename)));
            }

            byte[] transportCertData = Cert.parseCertificate(encoded);
            X509Certificate transportCert = manager.importCACertPackage(transportCertData);

            // get archival and key wrap mechanisms from CA
            CAInfoClient caInfoClient = new CAInfoClient(client, "ca");
            String kwAlg = caInfoClient.getKeyWrapAlgotihm();
            KeyWrapAlgorithm keyWrapAlgorithm = KeyWrapAlgorithm.fromString(kwAlg);

            SignatureAlgorithm signatureAlgorithm;
            if (algorithm.equals("rsa")) {
                signatureAlgorithm = SignatureAlgorithm.RSASignatureWithSHA256Digest;

            } else if (algorithm.equals("ec")) {
                signatureAlgorithm = SignatureAlgorithm.ECSignatureWithSHA256Digest;

            } else {
                throw new Exception("Unknown algorithm: " + algorithm);
            }

            csr = nssdb.createCRMFRequest(
                    token,
                    keyPair,
                    transportCert,
                    subjectDN,
                    attributeEncoding,
                    signatureAlgorithm,
                    withPop,
                    keyWrapAlgorithm,
                    useOAEP,
                    false); // useSharedSecret

        } else {
            throw new Exception("Unknown request type: " + requestType);
        }

        logger.info("CSR:\n" + csr);

        CAClient caClient = new CAClient(client);
        CACertClient certClient = new CACertClient(caClient);

        logger.info("Retrieving " + profileID + " profile");

        CertEnrollmentRequest request = certClient.getEnrollmentTemplate(profileID);

        // Key Generation / Dual Key Generation
        for (ProfileInput input : request.getInputs()) {

            ProfileAttribute typeAttr = input.getAttribute("cert_request_type");
            if (typeAttr != null) {
                typeAttr.setValue(requestType);
            }

            ProfileAttribute csrAttr = input.getAttribute("cert_request");
            if (csrAttr != null) {
                csrAttr.setValue(csr);
            }
        }

        // parse subject DN and put the values in a map
        DN dn = new DN(subjectDN);
        Vector<?> rdns = dn.getRDNs();

        Map<String, String> subjectAttributes = new HashMap<>();
        for (int i = 0; i < rdns.size(); i++) {
            RDN rdn = (RDN) rdns.elementAt(i);
            String type = rdn.getTypes()[0].toLowerCase();
            String value = rdn.getValues()[0];
            subjectAttributes.put(type, value);
        }

        ProfileInput sn = request.getInput("Subject Name");
        if (sn != null) {
            logger.info("Subject Name:");

            for (ProfileAttribute attribute : sn.getAttributes()) {
                String name = attribute.getName();
                String value = null;

                if (name.equals("subject")) {
                    // get the whole subject DN
                    value = subjectDN;

                } else if (name.startsWith("sn_")) {
                    // get value from subject DN
                    value = subjectAttributes.get(name.substring(3));

                } else {
                    // unknown attribute, ignore
                    logger.info("- " + name);
                    continue;
                }

                if (value == null)
                    continue;

                logger.info("- " + name + ": " + value);
                attribute.setValue(value);
            }
        }

        if (certRequestUsername != null) {
            request.setAttribute("uid", certRequestUsername);
        }

        if (cmd.hasOption("password")) {
            Console console = System.console();
            String certRequestPassword = new String(console.readPassword("Password: "));
            request.setAttribute("pwd", certRequestPassword);
        }

        logger.info("Sending certificate request");

        CertRequestInfos infos = certClient.enrollRequest(request, aid, adn);

        CACertRequestCLI.printCertRequestInfos(infos);
    }

    public String createPKCS10Request(
            NSSDatabase nssdb,
            KeyPair keyPair,
            String subjectDN) throws Exception {

        PublicKey publicKey = keyPair.getPublic();
        X509Key key = CryptoUtil.createX509Key(publicKey);

        String keyAlgorithm;
        if (publicKey instanceof RSAPublicKey) {
            keyAlgorithm = "SHA256withRSA";
        } else if (CryptoUtil.isECCKey(key)) {
            keyAlgorithm = "SHA256withEC";
        } else if (publicKey instanceof DSAPublicKey) {
            keyAlgorithm = "DSA";
        } else {
            throw new NoSuchAlgorithmException("Unsupported algorithm: " + publicKey.getAlgorithm());
        }

        Extensions extensions = new Extensions();

        PKCS10 pkcs10 = nssdb.createPKCS10Request(
                keyPair,
                subjectDN,
                keyAlgorithm,
                extensions);

        return CertUtil.toPEM(pkcs10);
    }
}
