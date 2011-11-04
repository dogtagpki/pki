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
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.PBEAlgorithm;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.CertBag;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;
import org.mozilla.jss.util.Password;


/**
 * Tool for creating PKCS12 file
 * 
 * <P>
 * @version $Revision$, $Date$
 *
 */
public class PKCS12Export {

    private static boolean debugMode = false;

    private static void debug(String s) {
        if (debugMode)
            System.out.println("PKCS12Export debug: " + s);    
    }

    private static void printUsage() {
        System.out.println("Usage: PKCS12Export -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
        System.out.println("");
        System.out.println("If you want to turn on debug, do the following:");
        System.out.println("Usage: PKCS12Export -debug -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
    }

    private static byte[] getEncodedKey(org.mozilla.jss.crypto.PrivateKey pkey) {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken token = cm.getInternalKeyStorageToken();
            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
            SymmetricKey sk = kg.generate();
            KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
            byte iv[] = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1};
            IVParameterSpec param = new IVParameterSpec(iv);
            wrapper.initWrap(sk, param);
            byte[] enckey = wrapper.wrap(pkey);
            Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
            c.initDecrypt(sk, param);
            byte[] recovered = c.doFinal(enckey);
            return recovered;
        } catch (Exception e) {
            debug("PKCS12Export  getEncodedKey: Exception="+e.toString());
            System.exit(1);
        }

        return null;
    }

    private static void addKeyBag(org.mozilla.jss.crypto.PrivateKey pkey, X509Certificate x509cert,
      Password pass, byte[] localKeyId, SEQUENCE safeContents) {
        try {
            PasswordConverter passConverter = new PasswordConverter();
            byte salt[] = {0x01, 0x01, 0x01, 0x01};
            byte[] priData = getEncodedKey(pkey);

            PrivateKeyInfo pki = (PrivateKeyInfo)
              ASN1Util.decode(PrivateKeyInfo.getTemplate(), priData);
            ASN1Value key = EncryptedPrivateKeyInfo.createPBE(
              PBEAlgorithm.PBE_SHA1_DES3_CBC,
              pass, salt, 1, passConverter, pki);
            SET keyAttrs = createBagAttrs(
              x509cert.getSubjectDN().toString(), localKeyId);
            SafeBag keyBag = new SafeBag(SafeBag.PKCS8_SHROUDED_KEY_BAG,
              key, keyAttrs);
            safeContents.addElement(keyBag);
        } catch (Exception e) {
            debug("PKCS12Export addKeyBag: Exception="+e.toString());
            System.exit(1);
        }
    }

    private static byte[] addCertBag(X509Certificate x509cert, String nickname,
      SEQUENCE safeContents) throws IOException {
        byte[] localKeyId = null;
        try {
            ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
            localKeyId = createLocalKeyId(x509cert);
            SET certAttrs = null;
            if (nickname != null)
                certAttrs = createBagAttrs(nickname, localKeyId);
            SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
              new CertBag(CertBag.X509_CERT_TYPE, cert), certAttrs);
            safeContents.addElement(certBag);
        } catch (Exception e) {
            debug("PKCS12Export addCertBag: "+e.toString());
            System.exit(1);
        }

        return localKeyId;
    }

    private static byte[] createLocalKeyId(X509Certificate cert) {
        try {
            // SHA1 hash of the X509Cert der encoding
            byte certDer[] = cert.getEncoded();

            MessageDigest md = MessageDigest.getInstance("SHA");

            md.update(certDer);
            return md.digest();
        } catch (Exception e) {
            debug("PKCS12Export createLocalKeyId: Exception: "+e.toString());
            System.exit(1);
        }

        return null;
    }

    private static SET createBagAttrs(String nickName, byte localKeyId[])
      throws IOException {
        try {
            SET attrs = new SET();
            SEQUENCE nickNameAttr = new SEQUENCE();

            nickNameAttr.addElement(SafeBag.FRIENDLY_NAME);
            SET nickNameSet = new SET();

            nickNameSet.addElement(new BMPString(nickName));
            nickNameAttr.addElement(nickNameSet);
            attrs.addElement(nickNameAttr);
            SEQUENCE localKeyAttr = new SEQUENCE();

            localKeyAttr.addElement(SafeBag.LOCAL_KEY_ID);
            SET localKeySet = new SET();

            localKeySet.addElement(new OCTET_STRING(localKeyId));
            localKeyAttr.addElement(localKeySet);
            attrs.addElement(localKeyAttr);
            return attrs;
        } catch (Exception e) {
            debug("PKCS12Export createBagAttrs: Exception="+e.toString());
            System.exit(1);
        }

        return null;
    }

    public static void main(String args[]) {
        if (args.length < 8) {
            printUsage();
            System.exit(1);
        }

        String pwdfile = null;
        String dir = null;
        String snickname = null;
        String pk12pwdfile = null;
        String pk12output = null;
        for (int i=0; i<args.length; i++) {
            if (args[i].equals("-d")) {
                dir = args[i+1];
            } else if (args[i].equals("-p")) {
                pwdfile = args[i+1];
            } else if (args[i].equals("-s")) {
                snickname = args[i+1];
            } else if (args[i].equals("-w")) {
                pk12pwdfile = args[i+1];
            } else if (args[i].equals("-o")) {
                pk12output = args[i+1];
            } else if (args[i].equals("-debug")) {
                debugMode = true;
            }
        }

        debug("The directory for certdb/keydb is "+dir);
        debug("The password file for keydb is "+pwdfile);

        // get password
        String pwd = null;
        try {
            BufferedReader in = new BufferedReader(new FileReader(pwdfile));
            pwd = in.readLine();
        } catch (Exception e) {
            debug("Failed to read the keydb password from the file. Exception: "+e.toString());
            System.exit(1);
        }

        String pk12pwd = null;
        try {
            BufferedReader in = new BufferedReader(new FileReader(pk12pwdfile));
            pk12pwd = in.readLine();
        } catch (Exception e) {
            debug("Failed to read the keydb password from the file. Exception: "+e.toString());
            System.exit(1);
        }

        CryptoManager cm = null;
        try {
            CryptoManager.InitializationValues vals = 
              new CryptoManager.InitializationValues(dir, "", "", "secmod.db");
            CryptoManager.initialize(vals);
            cm = CryptoManager.getInstance();
        } catch (Exception e) {
            debug("Failed to initialize the certdb.");
            System.exit(1);
        }

        SEQUENCE encSafeContents = new SEQUENCE();
        SEQUENCE safeContents = new SEQUENCE();
        try {
            CryptoToken token = cm.getInternalKeyStorageToken();
            Password pass = new Password(pwd.toCharArray());
            token.login(pass);
            CryptoStore store = token.getCryptoStore();
            X509Certificate[] certs = store.getCertificates();
            debug("Number of user certificates = "+certs.length);
            Password pass12 = new Password(pk12pwd.toCharArray());
            for (int i=0; i<certs.length; i++) {
                String nickname = certs[i].getNickname();
                debug("Certificate nickname = "+nickname);
                org.mozilla.jss.crypto.PrivateKey prikey = null;
                try {
                    prikey = cm.findPrivKeyByCert(certs[i]);
                } catch (Exception e) {
                    debug("PKCS12Export Exception: "+e.toString());
                }

                if (prikey == null) {
                    debug("Private key is null");
                    byte[] localKeyId = addCertBag(certs[i], null, safeContents);
                } else {
                    debug("Private key is not null");
                    byte localKeyId[] = 
                      addCertBag(certs[i], nickname, safeContents);
                    addKeyBag(prikey, certs[i], pass12, localKeyId, encSafeContents);
                }
            }

            AuthenticatedSafes authSafes = new AuthenticatedSafes();
            authSafes.addSafeContents(safeContents);
            authSafes.addSafeContents(encSafeContents);
            PFX pfx = new PFX(authSafes);
            pfx.computeMacData(pass12, null, 5);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            pfx.encode(bos);
            FileOutputStream fos = new FileOutputStream(pk12output);
            fos.write(bos.toByteArray());
            fos.flush();
            fos.close();
            pass.clear();
            pass12.clear();
        } catch (Exception e) {
            debug("PKCS12Export Exception: "+e.toString());
            System.exit(1);
        }
    }
}
