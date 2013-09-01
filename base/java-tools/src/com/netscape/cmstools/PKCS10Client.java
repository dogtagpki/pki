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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

import netscape.security.pkcs.PKCS10;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509Key;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.PrintableString;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.asn1.TeletexString;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.asn1.UniversalString;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs10.CertificationRequestInfo;
import org.mozilla.jss.pkix.primitive.AVA;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.HMACDigest;
import com.netscape.cmsutil.util.Utils;

/**
 * Generates an ECC or RSA key pair in the security database, constructs a
 * PKCS#10 certificate request with the public key, and outputs the request
 * to a file.
 * <p>
 * PKCS #10 is a certification request syntax standard defined by RSA. A CA may support multiple types of certificate
 * requests. The Certificate System CA supports KEYGEN, PKCS#10, CRMF, and CMC.
 * <p>
 * To get a certificate from the CA, the certificate request needs to be submitted to and approved by a CA agent. Once
 * approved, a certificate is created for the request, and certificate attributes, such as extensions, are populated
 * according to certificate profiles.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class PKCS10Client {

    private static void printUsage() {
        System.out.println(
                "Usage: PKCS10Client -d <location of certdb> -h <token name> -p <token password> -a <algorithm: 'rsa' or 'ec'> -l <rsa key length> -c <ec curve name> -o <output file which saves the base64 PKCS10> -n <subjectDN>\n");
        System.out.println(
                "    Optionally, for ECC key generation per definition in JSS pkcs11.PK11KeyPairGenerator:\n");
        System.out.println(
                "    -k <true for enabling encoding of attribute values; false for default encoding of attribute values; default is false>\n");
        System.out.println(
                "    -t <true for temporary(session); false for permanent(token); default is false>\n");
        System.out.println(
                "    -s <1 for sensitive; 0 for non-sensitive; -1 temporaryPairMode dependent; default is -1>\n");
        System.out.println(
                "    -e <1 for extractable; 0 for non-extractable; -1 token dependent; default is -1>\n");
        System.out.println(
                "    Also optional for ECC key generation:\n");
        System.out.println(
                "    -x <true for SSL cert that does ECDH ECDSA; false otherwise; default false>\n");
        System.out.println(
                "   available ECC curve names (if provided by the crypto module): nistp256 (secp256r1),nistp384 (secp384r1),nistp521 (secp521r1),nistk163 (sect163k1),sect163r1,nistb163 (sect163r2),sect193r1,sect193r2,nistk233 (sect233k1),nistb233 (sect233r1),sect239k1,nistk283 (sect283k1),nistb283 (sect283r1),nistk409 (sect409k1),nistb409 (sect409r1),nistk571 (sect571k1),nistb571 (sect571r1),secp160k1,secp160r1,secp160r2,secp192k1,nistp192 (secp192r1, prime192v1),secp224k1,nistp224 (secp224r1),secp256k1,prime192v2,prime192v3,prime239v1,prime239v2,prime239v3,c2pnb163v1,c2pnb163v2,c2pnb163v3,c2pnb176v1,c2tnb191v1,c2tnb191v2,c2tnb191v3,c2pnb208w1,c2tnb239v1,c2tnb239v2,c2tnb239v3,c2pnb272w1,c2pnb304w1,c2tnb359w1,c2pnb368w1,c2tnb431r1,secp112r1,secp112r2,secp128r1,secp128r2,sect113r1,sect113r2,sect131r1,sect131r2\n");
    }

    public static void main(String args[]) throws Exception {
        String dbdir = null, ofilename = null, password = null, subjectName = null, tokenName = null;

        String alg = "rsa";
        String ecc_curve = "nistp256";
        boolean ec_temporary = false; /* session if true; token if false */
        boolean enable_encoding = false; /* enable encoding attribute values if true */
        int ec_sensitive = -1; /* -1, 0, or 1 */
        int ec_extractable = -1; /* -1, 0, or 1 */
        boolean ec_ssl_ecdh = false;
        int rsa_keylen = 2048;

        if (args.length < 4) {
            printUsage();
            System.exit(1);
        }

        for (int i = 0; i < args.length; i+=2) {
            String name = args[i];

            if (name.equals("-p")) {
                password = args[i+1];
            } else if (name.equals("-d")) {
                dbdir = args[i+1];
            } else if (name.equals("-a")) {
                alg = args[i+1];
                if (!alg.equals("rsa") && !alg.equals("ec")) {
                    System.out.println("PKCS10Client: ERROR: invalid algorithm: " + alg);
                    System.exit(1);
                }
            } else if (name.equals("-x")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    ec_ssl_ecdh = true;
                else
                    ec_ssl_ecdh = false;
            } else if (name.equals("-t")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    ec_temporary = true;
                else
                    ec_temporary = false;
            } else if (name.equals("-k")) {
                String temp = args[i+1];
                if (temp.equals("true"))
                    enable_encoding = true;
                else
                    enable_encoding = false;
            } else if (name.equals("-s")) {
                String ec_sensitive_s = args[i+1];
                ec_sensitive = Integer.parseInt(ec_sensitive_s);
                if ((ec_sensitive != 0) &&
                    (ec_sensitive != 1) &&
                    (ec_sensitive != -1)) {
                      System.out.println("PKCS10Client: Illegal input parameters for -s.");
                      printUsage();
                      System.exit(1);
                    }
            } else if (name.equals("-e")) {
                String ec_extractable_s = args[i+1];
                ec_extractable = Integer.parseInt(ec_extractable_s);
                if ((ec_extractable != 0) &&
                    (ec_extractable != 1) &&
                    (ec_extractable != -1)) {
                      System.out.println("PKCS10Client: Illegal input parameters for -e.");
                      printUsage();
                      System.exit(1);
                    }
            } else if (name.equals("-c")) {
                ecc_curve = args[i+1];
            } else if (name.equals("-l")) {
                rsa_keylen = Integer.parseInt(args[i+1]);
            } else if (name.equals("-o")) {
                ofilename = args[i+1];
            } else if (name.equals("-n")) {
                subjectName = args[i+1];
            } else if (name.equals("-h")) {
                tokenName = args[i+1];
            } else {
                System.out.println("Unrecognized argument(" + i + "): "
                    + name);
                printUsage();
                System.exit(1);
            }
        }

        if (password == null || ofilename == null || subjectName == null) {
            System.out.println("PKCS10Client: Illegal input parameters.");
            printUsage();
            System.exit(1);
        }

        if (dbdir == null)
            dbdir = ".";

        try {
            // initialize CryptoManager
            String mPrefix = "";
            CryptoManager.InitializationValues vals =
                new CryptoManager.InitializationValues(dbdir, mPrefix,
                        mPrefix, "secmod.db");

            CryptoManager.initialize(vals);
            CryptoToken token = null;
            CryptoManager cm = CryptoManager.getInstance();
            if ((tokenName == null) || (tokenName.equals(""))) {
                token = cm.getInternalKeyStorageToken();
                tokenName = token.getName();
            } else {
                token = cm.getTokenByName(tokenName);
            }
            System.out.println("PKCS10Client: Debug: got token.");
            cm.setThreadToken(token);
            System.out.println("PKCS10Client: Debug: thread token set.");

            Password pass = new Password(password.toCharArray());

            try {
                token.login(pass);
                System.out.println("PKCS10Client: token "+ tokenName + " logged in...");
            } catch (Exception e) {
                System.out.println("PKCS10Client: login Exception: " + e.toString());
                System.exit(1);
            }

            KeyPair pair = null;

            if (alg.equals("rsa")) {
                KeyPairGenerator kg = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
                kg.initialize(rsa_keylen);
                pair = kg.genKeyPair();
            }  else if (alg.equals("ec")) {
                // used with SSL server cert that does ECDH ECDSA
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask_ECDH[] = {
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN,
                    org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.SIGN_RECOVER
                };

                // used for other certs including SSL server cert that does ECDHE ECDSA
                org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage usages_mask[] = {
                  org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage.DERIVE
                };

                pair = CryptoUtil.generateECCKeyPair(tokenName,  ecc_curve ,
                       null,
                       usages_mask, ec_temporary /*temporary*/,
                       ec_sensitive /*sensitive*/, ec_extractable /*extractable*/);
                if (pair == null) {
                    System.out.println("PKCS10Client: pair null.");
                    System.exit(1);
                }
            }

            System.out.println("PKCS10Client: key pair generated."); //key pair generated");

            // Add idPOPLinkWitness control
            String secretValue = "testing";
            byte[] key1 = null;
            byte[] finalDigest = null;
            MessageDigest SHA1Digest = MessageDigest.getInstance("SHA1");
            key1 = SHA1Digest.digest(secretValue.getBytes());

            /* seed */
            byte[] b =
            { 0x10, 0x53, 0x42, 0x24, 0x1a, 0x2a, 0x35, 0x3c,
                0x7a, 0x52, 0x54, 0x56, 0x71, 0x65, 0x66, 0x4c,
                0x51, 0x34, 0x35, 0x23, 0x3c, 0x42, 0x43, 0x45,
                0x61, 0x4f, 0x6e, 0x43, 0x1e, 0x2a, 0x2b, 0x31,
                0x32, 0x34, 0x35, 0x36, 0x55, 0x51, 0x48, 0x14,
                0x16, 0x29, 0x41, 0x42, 0x43, 0x7b, 0x63, 0x44,
                0x6a, 0x12, 0x6b, 0x3c, 0x4c, 0x3f, 0x00, 0x14,
                0x51, 0x61, 0x15, 0x22, 0x23, 0x5f, 0x5e, 0x69 };

            HMACDigest hmacDigest = new HMACDigest(SHA1Digest, key1);
            hmacDigest.update(b);
            finalDigest = hmacDigest.digest();

            OCTET_STRING ostr = new OCTET_STRING(finalDigest);
            Attribute attr = new Attribute(OBJECT_IDENTIFIER.id_cmc_idPOPLinkWitness, ostr);

            SET attributes = new SET();
            attributes.addElement(attr);
            Name n = getJssName(enable_encoding, subjectName);
            SubjectPublicKeyInfo subjectPub = new SubjectPublicKeyInfo(pair.getPublic());
            System.out.println("PKCS10Client: pair.getPublic() called.");
            CertificationRequestInfo certReqInfo =
                new CertificationRequestInfo(new INTEGER(0), n, subjectPub, attributes);
            System.out.println("PKCS10Client: CertificationRequestInfo() created.");

            String b64E = "";
            if (alg.equals("rsa")) {
                CertificationRequest certRequest = null;
                certRequest = new CertificationRequest(certReqInfo,
                pair.getPrivate(), SignatureAlgorithm.RSASignatureWithMD5Digest);
                System.out.println("PKCS10Client: CertificationRequest created.");

                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                certRequest.encode(bos);
                byte[] bb = bos.toByteArray();

                System.out.println("PKCS10Client: calling Utils.b64encode.");
                b64E = Utils.base64encode(bb);
                System.out.println("PKCS10Client: b64encode completes.");
            } else { // "ec"

                CryptoToken t = cm.getThreadToken();
                System.out.println("PKCS10Client: token is: "+ t.getName());
                PublicKey pubk =  pair.getPublic();
                if (pubk == null) {
                    System.out.println("PKCS10Client: pubk null.");
                    System.exit(1);
                }
                X509Key xKey = null;
                byte pubk_encoded[] =  pubk.getEncoded();
                xKey = CryptoUtil.getPublicX509ECCKey(pubk_encoded);
                System.out.println("PKCS10Client: calling CryptoUtil.createCertificationRequest");
                PKCS10 certReq = CryptoUtil.createCertificationRequest(
                    subjectName, xKey, (org.mozilla.jss.crypto.PrivateKey) pair.getPrivate(),
                    "SHA256withEC");

                System.out.println("PKCS10Client: created cert request");
                if (certReq == null) {
                    System.out.println("PKCS10Client: cert request null");
                    System.exit(1);
                } else
                    System.out.println("PKCS10Client: cert request not null");
                byte[] certReqb = certReq.toByteArray();
                b64E = CryptoUtil.base64Encode(certReqb);
            }

            System.out.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
            System.out.println(b64E);
            System.out.println("-----END NEW CERTIFICATE REQUEST-----");

            PrintStream ps = null;
            ps = new PrintStream(new FileOutputStream(ofilename));
            ps.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
            ps.println(b64E);
            ps.println("-----END NEW CERTIFICATE REQUEST-----");
            ps.flush();
            ps.close();
            System.out.println("PKCS10Client: done. Request written to file: "+ ofilename);
        } catch (Exception e) {
            System.out.println("PKCS10Client: Exception caught: "+e.toString());
        }

    }

    static boolean isEncoded (String elementValue) {
        boolean encoded = false;

        if (elementValue != null && ((elementValue.startsWith("UTF8String:")) ||
                                     (elementValue.startsWith("PrintableString:")) ||
                                     (elementValue.startsWith("BMPString:")) ||
                                     (elementValue.startsWith("TeletexString:")) ||
                                     (elementValue.startsWith("UniversalString:")))) {
            encoded = true;
        }
        return encoded;
    }

    static Name addNameElement (Name name, OBJECT_IDENTIFIER oid, int n, String elementValue) {
        try {
            String encodingType = (n > 0)? elementValue.substring(0, n): null;
            String nameValue = (n > 0)? elementValue.substring(n+1): null;
            if (encodingType != null && encodingType.length() > 0 &&
                nameValue != null && nameValue.length() > 0) {
                if (encodingType.equals("UTF8String")) {
                    name.addElement( new AVA(oid, new UTF8String(nameValue)));
                } else if (encodingType.equals("PrintableString")) {
                    name.addElement( new AVA(oid, new PrintableString(nameValue)));
                } else if (encodingType.equals("BMPString")) {
                    name.addElement( new AVA(oid, new BMPString(nameValue)));
                } else if (encodingType.equals("TeletexString")) {
                    name.addElement( new AVA(oid, new TeletexString(nameValue)));
                } else if (encodingType.equals("UniversalString")) {
                    name.addElement( new AVA(oid, new UniversalString(nameValue)));
                }
            }
        }  catch (Exception e)  {
            System.out.println("PKCS10Client: Error adding name element: " + elementValue + " Error: "  + e.toString());
        }
        return name;
    }

    static Name getJssName(boolean enable_encoding, String dn) {

        X500Name x5Name = null;

        try {
            x5Name = new X500Name(dn);
        } catch (IOException e) {

            System.out.println("PKCS10Client: Illegal Subject Name:  " + dn + " Error: " + e.toString());
            System.out.println("PKCS10Client: Filling in default Subject Name......");
            return null;
        }

        Name ret = new Name();
        netscape.security.x509.RDN[] names = null;
        names = x5Name.getNames();
        int nameLen = x5Name.getNamesLength();

        netscape.security.x509.RDN cur = null;

        for (int i = 0; i < nameLen; i++) {
            cur = names[i];
            String rdnStr = cur.toString();
            String[] split = rdnStr.split("=");

            if (split.length != 2)
                continue;
            int n = split[1].indexOf(':');

            try {
                if (split[0].equals("UID")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement(ret, new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),
                                             n, split[1]);
                    } else {
                        ret.addElement(new AVA(new OBJECT_IDENTIFIER("0.9.2342.19200300.100.1.1"),
                                               new PrintableString(split[1])));
                    }
                    //                 System.out.println("UID found : " + split[1]);
                }

                if (split[0].equals("C")) {
                    ret.addCountryName(split[1]);
                    //                   System.out.println("C found : " + split[1]);
                    continue;
                }

                if (split[0].equals("CN")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.commonName, n, split[1]);
                    } else {
                        ret.addCommonName(split[1]);
                    }
                    //                  System.out.println("CN found : " + split[1]);
                    continue;
                }

                if (split[0].equals("L")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.localityName, n, split[1]);
                    } else {
                        ret.addLocalityName(split[1]);
                    }
                    //                 System.out.println("L found : " + split[1]);
                    continue;
                }

                if (split[0].equals("O")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.organizationName, n, split[1]);
                    } else {
                        ret.addOrganizationName(split[1]);
                    }
                    //                System.out.println("O found : " + split[1]);
                    continue;
                }

                if (split[0].equals("ST")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.stateOrProvinceName, n, split[1]);
                    } else {
                        ret.addStateOrProvinceName(split[1]);
                    }
                    //               System.out.println("ST found : " + split[1]);
                    continue;
                }

                if (split[0].equals("OU")) {
                    if (enable_encoding && isEncoded(split[1])) {
                        ret = addNameElement (ret, Name.organizationalUnitName, n, split[1]);
                    } else {
                        ret.addOrganizationalUnitName(split[1]);
                    }
                    //              System.out.println("OU found : " + split[1]);
                    continue;
                }
            } catch (Exception e) {
                System.out.println("PKCS10Client: Error constructing RDN: " + rdnStr + " Error: " + e.toString());
                continue;
            }
        }

        return ret;
    }
}
