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
package com.netscape.cmstools;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

import netscape.security.x509.X500Name;

import org.apache.commons.io.FileUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.crmf.POPOSigningKey;
import org.mozilla.jss.pkix.crmf.ProofOfPossession;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.HMACDigest;
import com.netscape.cmsutil.util.Utils;

/**
 * A command-line utility used to generate a Certificate Request Message
 * Format (CRMF) request with proof of possesion (POP).
 *
 * <pre>
 * IMPORTANT:  The transport certificate file needs to be created to contain the
 *             transport certificate in its base64 encoded format.
 * </pre>
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class CRMFPopClient {

    public boolean verbose;

    private static void usage() {

        System.out.println("Usage: CRMFPopClient -d <location of certdb> -p <token password> -h <tokenname> -o <output file which saves the base64 CRMF request> -n <subjectDN> -a <algorithm: 'rsa' or 'ec'> -l <rsa key length> -c <ec curve name> -m <hostname:port> -f <profile name; rsa default caEncUserCert; ec default caEncECUserCert> -u <user name> -r <requestor name> -q <POP_NONE, POP_SUCCESS, or POP_FAIL; default POP_SUCCESS> \n");
        System.out.println("    Optionally, for ECC key generation per definition in JSS pkcs11.PK11KeyPairGenerator:\n");
        System.out.println("    -k <true for enabling encoding of attribute values; false for default encoding of attribute values; default is false>\n");
        System.out.println("    -t <true for temporary(session); false for permanent(token); default is true>\n");
        System.out.println("    -s <1 for sensitive; 0 for non-sensitive; -1 temporaryPairMode dependent; default is -1>\n");
        System.out.println("    -e <1 for extractable; 0 for non-extractable; -1 token dependent; default is -1>\n");
        System.out.println("    Also optional for ECC key generation:\n");
        System.out.println("    -x <true for SSL cert that does ECDH ECDSA; false otherwise; default false>\n");
        System.out.println("    --transport-cert <transport cert file; default transport.txt>\n");
        System.out.println(" note: '-x true' can only be used with POP_NONE");
        System.out.println("   available ECC curve names (if provided by the crypto module): nistp256 (secp256r1),nistp384 (secp384r1),nistp521 (secp521r1),nistk163 (sect163k1),sect163r1,nistb163 (sect163r2),sect193r1,sect193r2,nistk233 (sect233k1),nistb233 (sect233r1),sect239k1,nistk283 (sect283k1),nistb283 (sect283r1),nistk409 (sect409k1),nistb409 (sect409r1),nistk571 (sect571k1),nistb571 (sect571r1),secp160k1,secp160r1,secp160r2,secp192k1,nistp192 (secp192r1, prime192v1),secp224k1,nistp224 (secp224r1),secp256k1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2\n");

        System.out.println("\n");
        System.out.println("IMPORTANT:  The transport certificate file needs to be created to contain the");
        System.out.println("            transport certificate in its base64 encoded format.");
    }

    public static void main(String args[]) throws Exception {

        CRMFPopClient client = new CRMFPopClient();

        String databaseDir = ".";
        String tokenPassword = null;
        String tokenName = null;

        // "rsa" or "ec"
        String algorithm = "rsa";

        /* default RSA key size */
        int keySize = 2048;

        /* default ECC key curve name */
        String curve = "nistp256";

        boolean encodingEnabled = false; /* enable encoding attribute values if true */
        boolean temporary = true; /* session if true; token if false */
        int sensitive = -1; /* -1, 0, or 1 */
        int extractable = -1; /* -1, 0, or 1 */
        boolean sslECDH = false;

        String username = null;
        String requestor = null;
        String profileName = null;

        // format: "host:port"
        String hostPort = null;
        String subjectDN = null;
        boolean submitRequest = false;

        // POP_NONE, POP_SUCCESS, or POP_FAIL
        String popOption = "POP_SUCCESS";
        boolean withPop = true;

        String output = null;
        String transportCertFilename = "transport.txt";

        for (int i=0; i<args.length; i+=2) {
            String name = args[i];

            if (name.equals("-v")) {
                client.verbose = Boolean.parseBoolean(args[i+1]);

            } else if (name.equals("-p")) {
                tokenPassword = args[i+1];

            } else if (name.equals("-d")) {
                databaseDir = args[i+1];

            } else if (name.equals("-h")) {
                tokenName = args[i+1];

            } else if (name.equals("-a")) {
                algorithm = args[i+1];
                if (!algorithm.equals("rsa") && !algorithm.equals("ec")) {
                    System.out.println("ERROR: invalid algorithm: " + algorithm);
                    System.exit(1);
                }

            } else if (name.equals("-x")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    sslECDH = true;
                else
                    sslECDH = false;

            } else if (name.equals("-t")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    temporary = true;
                else
                    temporary = false;
            } else if (name.equals("-k")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    encodingEnabled = true;
                else
                    encodingEnabled = false;

            } else if (name.equals("-s")) {
                String ec_sensitive_s = args[i+1];
                sensitive = Integer.parseInt(ec_sensitive_s);
                if ((sensitive != 0) &&
                    (sensitive != 1) &&
                    (sensitive != -1)) {
                      System.out.println("ERROR: Illegal input parameters for -s.");
                      usage();
                      System.exit(1);
                    }

            } else if (name.equals("-e")) {
                String ec_extractable_s = args[i+1];
                extractable = Integer.parseInt(ec_extractable_s);
                if ((extractable != 0) &&
                    (extractable != 1) &&
                    (extractable != -1)) {
                      System.out.println("ERROR: Illegal input parameters for -e.");
                      usage();
                      System.exit(1);
                    }

            } else if (name.equals("-l")) {
                keySize = Integer.parseInt(args[i+1]);

            } else if (name.equals("-c")) {
                curve = args[i+1];

            } else if (name.equals("-m")) {
                hostPort = args[i+1];
                submitRequest = true;

            } else if (name.equals("-f")) {
                profileName = args[i+1];

            } else if (name.equals("-u")) {
                username = args[i+1];

            } else if (name.equals("-r")) {
                requestor = args[i+1];

            } else if (name.equals("-n")) {
                subjectDN = args[i+1];

            } else if (name.equals("-q")) {
                popOption = args[i+1];
                if (!popOption.equals("POP_SUCCESS") &&
                    !popOption.equals("POP_FAIL") &&
                    !popOption.equals("POP_NONE")) {
                    System.out.println("ERROR: invalid POP option: "+ popOption);
                    System.exit(1);
                }
                if (popOption.equals("POP_NONE"))
                    withPop = false;

            } else if (name.equals("-o")) {
                output = args[i+1];

            } else if (name.equals("--transport-cert")) {
                transportCertFilename = args[i+1];

            } else {
                System.out.println("Unrecognized argument(" + i + "): "
                    + name);
                usage();
                System.exit(1);
            }
        }

        if (tokenPassword == null) {
           System.out.println("missing password");
           usage();
           System.exit(1);
        }

        if (profileName == null) {
            if (algorithm.equals("rsa")) {
                profileName = "caEncUserCert";

            } else if (algorithm.equals("ec")) {
                profileName = "caEncECUserCert";

            } else {
                throw new Exception("Unknown algorithm: " + algorithm);
            }
        }

        try {
            if (client.verbose) System.out.println("Initializing security database");
            CryptoManager.initialize(databaseDir);

            CryptoManager manager = CryptoManager.getInstance();

            CryptoToken token;
            if (tokenName == null) {
                token = manager.getInternalKeyStorageToken();
                tokenName = token.getName();
            } else {
                token = manager.getTokenByName(tokenName);
            }
            manager.setThreadToken(token);

            Password password = new Password(tokenPassword.toCharArray());
            try {
                token.login(password);
            } catch (Exception e) {
                throw new Exception("Unable to login: " + e, e);
            }

            if (client.verbose) System.out.println("Loading transport certificate");
            String encoded = FileUtils.readFileToString(new File(transportCertFilename));
            encoded = Cert.normalizeCertStrAndReq(encoded);
            encoded = Cert.stripBrackets(encoded);
            byte[] transportCertData = Utils.base64decode(encoded);

            X509Certificate transportCert = manager.importCACertPackage(transportCertData);

            if (client.verbose) System.out.println("Parsing subject DN");
            Name subject = client.createName(subjectDN, encodingEnabled);

            if (subject == null) {
                subject = new Name();
                subject.addCommonName("Me");
                subject.addCountryName("US");
                subject.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),  new PrintableString("MyUid")));
            }

            if (client.verbose) System.out.println("Generating key pair");
            KeyPair keyPair;
            if (algorithm.equals("rsa")) {
                keyPair = client.generateRSAKeyPair(token, keySize);

            } else if (algorithm.equals("ec")) {
                keyPair = client.generateECCKeyPair(token, curve, sslECDH, temporary, sensitive, extractable);

            } else {
                throw new Exception("Unknown algorithm: " + algorithm);
            }

            if (client.verbose) System.out.println("Creating certificate request");
            CertRequest certRequest = client.createCertRequest(token, transportCert, algorithm, keyPair, subject);

            ProofOfPossession pop = null;

            if (withPop) {

                if (client.verbose) System.out.println("Creating signer");
                Signature signer = client.createSigner(token, algorithm, keyPair);

                if (popOption.equals("POP_SUCCESS")) {

                    ByteArrayOutputStream bo = new ByteArrayOutputStream();
                    certRequest.encode(bo);
                    signer.update(bo.toByteArray());

                } else if (popOption.equals("POP_FAIL")) {

                    byte[] data = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

                    signer.update(data);
                }

                byte[] signature = signer.sign();

                if (client.verbose) System.out.println("Creating POP");
                pop = client.createPop(algorithm, signature);
            }

            if (client.verbose) System.out.println("Creating CRMF requrest");
            String request = client.createCRMFRequest(certRequest, pop);

            StringWriter sw = new StringWriter();
            try (PrintWriter out = new PrintWriter(sw)) {
                out.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
                out.println(request);
                out.println("-----END NEW CERTIFICATE REQUEST-----");
            }
            String csr = sw.toString();

            if (submitRequest) {
                System.out.println("Submitting CRMF request to " + hostPort);
                client.submitRequest(
                        request,
                        hostPort,
                        username,
                        profileName,
                        requestor);

            } else if (output != null) {
                System.out.println("Storing CRMF requrest into " + output);
                try (FileWriter out = new FileWriter(output)) {
                    out.write(csr);
                }

            } else {
                System.out.println(csr);
            }

        } catch (Exception e) {
            System.out.println("ERROR: " + e);
            e.printStackTrace();
            System.exit(1);
        }
    }

    public KeyPair generateRSAKeyPair(CryptoToken token, int length) throws Exception {
        KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        kg.initialize(length);
        return kg.genKeyPair();
    }

    public KeyPair generateECCKeyPair(
            CryptoToken token,
            String curve,
            boolean sslECDH,
            boolean temporary,
            int sensitive,
            int extractable) throws Exception {
        /*
         * used with SSL server cert that does ECDH ECDSA
         *  ** can only be used with POP_NONE **
         */
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMaskECDH = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
        };

        /* used for other certs including SSL server cert that does ECDHE ECDSA */
        org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage[] usagesMask = {
            org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
        };

        return CryptoUtil.generateECCKeyPair(
                token.getName(),
                curve,
                null,
                sslECDH ? usagesMaskECDH : usagesMask,
                temporary,
                sensitive,
                extractable);
    }

    public byte[] wrapPrivateKey(CryptoToken token, SymmetricKey sessionKey, byte[] iv, KeyPair keyPair) throws Exception {

        // wrap private key using session
        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        wrapper.initWrap(sessionKey, new IVParameterSpec(iv));
        return wrapper.wrap((org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());
    }

    public byte[] wrapSessionKey(CryptoToken token, X509Certificate transportCert, SymmetricKey sessionKey) throws Exception {

        // wrap session key using KRA transport cert
        // currently, a transport cert has to be an RSA cert,
        // regardless of the key you are wrapping
        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.RSA);
        wrapper.initWrap(transportCert.getPublicKey(), null);
        return wrapper.wrap(sessionKey);
    }

    public CertRequest createCertRequest(
            CryptoToken token,
            X509Certificate transportCert,
            String algorithm,
            KeyPair keyPair,
            Name subject) throws Exception {

        PKIArchiveOptions opts = createPKIArchiveOptions(token, transportCert, algorithm, keyPair);
        CertTemplate certTemplate = createCertTemplate(subject, keyPair.getPublic());

        SEQUENCE seq = new SEQUENCE();
        seq.addElement(new AVA(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.5.1.4"), opts));

        OCTET_STRING ostr = createIDPOPLinkWitness();
        seq.addElement(new AVA(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr));

        return new CertRequest(new INTEGER(1), certTemplate, seq);
    }

    public OCTET_STRING createIDPOPLinkWitness() throws Exception {

        String secretValue = "testing";
        MessageDigest digest1 = MessageDigest.getInstance("SHA1");
        byte[] key1 = digest1.digest(secretValue.getBytes());

        /* Example of adding the POP link witness control to CRMF */
        byte[] b = {
            0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
            0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
            0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
            0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
            0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
            0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
            0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
            0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69
        };

        MessageDigest digest2 = MessageDigest.getInstance("SHA1");
        HMACDigest hmacDigest = new HMACDigest(digest2, key1);
        hmacDigest.update(b);
        byte[] finalDigest = hmacDigest.digest();

        return new OCTET_STRING(finalDigest);
    }

    public PKIArchiveOptions createPKIArchiveOptions(
            CryptoToken token,
            X509Certificate transportCert,
            String algorithm,
            KeyPair keyPair) throws Exception {

        KeyGenerator keyGen = token.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey sessionKey = keyGen.generate();

        byte[] iv = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

        byte[] wrappedPrivateKey = wrapPrivateKey(token, sessionKey, iv, keyPair);
        byte[] wrappedSessionKey = wrapSessionKey(token, transportCert, sessionKey);

        AlgorithmIdentifier algorithmID;
        if (algorithm.equals("rsa")) {
            algorithmID = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.113549.3.7"), new OCTET_STRING(iv));

        } else if (algorithm.equals("ec")) {
            algorithmID = new AlgorithmIdentifier(new OBJECT_IDENTIFIER("1.2.840.10045.2.1"), new OCTET_STRING(iv));

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        EncryptedValue encValue = new EncryptedValue(
                null,
                algorithmID,
                new BIT_STRING(wrappedSessionKey, 0),
                null,
                null,
                new BIT_STRING(wrappedPrivateKey, 0));

        EncryptedKey key = new EncryptedKey(encValue);

        return new PKIArchiveOptions(key);
    }

    public CertTemplate createCertTemplate(Name subject, PublicKey publicKey) throws Exception {

        CertTemplate template = new CertTemplate();
        template.setVersion(new INTEGER(2));
        template.setSubject(subject);
        template.setPublicKey(new SubjectPublicKeyInfo(publicKey));

        return template;
    }

    public Signature createSigner(
            CryptoToken token,
            String algorithm,
            KeyPair keyPair) throws Exception {

        Signature signer;
        if (algorithm.equals("rsa")) {
            signer =  token.getSignatureContext(SignatureAlgorithm.RSASignatureWithMD5Digest);

        } else if (algorithm.equals("ec")) {
            signer =  token.getSignatureContext(SignatureAlgorithm.ECSignatureWithSHA1Digest);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        signer.initSign((org.mozilla.jss.crypto.PrivateKey) keyPair.getPrivate());

        return signer;
    }

    public ProofOfPossession createPop(String algorithm, byte[] signature) throws Exception {

        AlgorithmIdentifier algorithmID;
        if (algorithm.equals("rsa")) {
            algorithmID = new AlgorithmIdentifier(SignatureAlgorithm.RSASignatureWithMD5Digest.toOID(), null);

        } else if (algorithm.equals("ec")) {
            algorithmID = new AlgorithmIdentifier(SignatureAlgorithm.ECSignatureWithSHA1Digest.toOID(), null);

        } else {
            throw new Exception("Unknown algorithm: " + algorithm);
        }

        POPOSigningKey popoKey = new POPOSigningKey(null, algorithmID, new BIT_STRING(signature, 0));
        return ProofOfPossession.createSignature(popoKey);
    }

    public String createCRMFRequest(
            CertRequest certRequest,
            ProofOfPossession pop) throws Exception {

        CertReqMsg crmfMessage = new CertReqMsg(certRequest, pop, null);
        //crmfMessage.verify();

        SEQUENCE seq = new SEQUENCE();
        seq.addElement(crmfMessage);

        byte[] encodedCrmfMessage = ASN1Util.encode(seq);
        return Utils.base64encode(encodedCrmfMessage);
    }

    public void submitRequest(
            String request,
            String hostPort,
            String username,
            String profileName,
            String requestor) throws Exception {

        String encodedRequest = URLEncoder.encode(request, "UTF-8");

        URL url = new URL(
                "http://" + hostPort + "/ca/ee/ca/profileSubmit"
                + "?cert_request_type=crmf"
                + "&cert_request=" + encodedRequest
                + "&renewal=false&uid=" + username
                + "&xmlOutput=false"
                + "&profileId=" + profileName
                + "&sn_uid=" + username
                + "&SubId=profile"
                + "&requestor_name=" + requestor);

        if (verbose) System.out.println("Opening " + url);

        URLConnection conn = url.openConnection();
        InputStream is = conn.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));

        if (verbose) System.out.println("--------------------");
        String line = null;
        String status = null;
        String requestId = null;
        while ((line = reader.readLine()) != null) {
            if (verbose) System.out.println(line);

            if (line.startsWith("errorCode=")) {
                int i = line.indexOf("\"");
                int j = line.indexOf("\";", i+1);
                String errorCode = line.substring(i+1, j);

                if ("0".equals(errorCode)) {
                    status = "completed";

                } else if ("1".equals(errorCode)) {
                    status = "failed";

                } else if ("2".equals(errorCode)) {
                    status = "pending";

                } else {
                    status = "unknown";
                }

            } else if (line.startsWith("requestList.requestId=")) {
                int i = line.indexOf("\"");
                int j = line.indexOf("\";", i+1);
                requestId = line.substring(i+1, j);
            }
        }
        if (verbose) System.out.println("--------------------");

        if (requestId != null) {
            System.out.println("Request ID: " + requestId);
        }

        if (status != null) {
            System.out.println("Request Status: " + status);
        }
    }

    public boolean isEncoded(String elementValue) {

        if (elementValue == null) return false;

        return elementValue.startsWith("UTF8String:")
                || elementValue.startsWith("PrintableString:")
                || elementValue.startsWith("BMPString:")
                || elementValue.startsWith("TeletexString:")
                || elementValue.startsWith("UniversalString:");
    }

    public AVA createAVA(OBJECT_IDENTIFIER oid, int n, String elementValue) throws Exception {

        String encodingType = n > 0 ? elementValue.substring(0, n) : null;
        String nameValue = n > 0 ? elementValue.substring(n+1) : null;

        if (encodingType != null && encodingType.length() > 0
                && nameValue != null && nameValue.length() > 0) {

            if (encodingType.equals("UTF8String")) {
                return new AVA(oid, new UTF8String(nameValue));

            } else if (encodingType.equals("PrintableString")) {
                return new AVA(oid, new PrintableString(nameValue));

            } else if (encodingType.equals("BMPString")) {
                return new AVA(oid, new BMPString(nameValue));

            } else if (encodingType.equals("TeletexString")) {
                return new AVA(oid, new TeletexString(nameValue));

            } else if (encodingType.equals("UniversalString")) {
                return new AVA(oid, new UniversalString(nameValue));

            } else {
                throw new Exception("Unsupported encoding: " + encodingType);
            }
        }

        return null;
    }

    public Name createName(String dn, boolean encodingEnabled) throws Exception {

        X500Name x500Name = new X500Name(dn);
        Name jssName = new Name();

        for (netscape.security.x509.RDN rdn : x500Name.getNames()) {

            String rdnStr = rdn.toString();
            if (verbose) System.out.println("RDN: " + rdnStr);

            String[] split = rdnStr.split("=");
            if (split.length != 2) continue;

            String attribute = split[0];
            String value = split[1];

            int n = value.indexOf(':');

            if (attribute.equalsIgnoreCase("UID")) {
                AVA ava;
                if (encodingEnabled && isEncoded(value)) {
                    ava = createAVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), n, value);
                } else {
                    ava = new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"), new PrintableString(value));
                }
                jssName.addElement(ava);

            } else if (attribute.equalsIgnoreCase("C")) {
                jssName.addCountryName(value);

            } else if (attribute.equalsIgnoreCase("CN")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.commonName, n, value));
                } else {
                    jssName.addCommonName(value);
                }

            } else if (attribute.equalsIgnoreCase("L")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.localityName, n, value));
                } else {
                    jssName.addLocalityName(value);
                }

            } else if (attribute.equalsIgnoreCase("O")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationName, n, value));
                } else {
                    jssName.addOrganizationName(value);
                }

            } else if (attribute.equalsIgnoreCase("ST")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.stateOrProvinceName, n, value));
                } else {
                    jssName.addStateOrProvinceName(value);
                }

            } else if (attribute.equalsIgnoreCase("OU")) {
                if (encodingEnabled && isEncoded(value)) {
                    jssName.addElement(createAVA(Name.organizationalUnitName, n, value));
                } else {
                    jssName.addOrganizationalUnitName(value);
                }

            } else {
                throw new Exception("Unsupported attribute: " + attribute);
            }
        }

        return jssName;
    }
}
