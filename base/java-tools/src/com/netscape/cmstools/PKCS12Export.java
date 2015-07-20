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
 *
 * @version $Revision$, $Date$
 *
 */
public class PKCS12Export {

    boolean debug;

    String databaseDirectory;
    String databasePasswordFilename;

    String pkcs12PasswordFilename;
    String pkcs12OutputFilename;

    public boolean isDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public String getDatabaseDirectory() {
        return databaseDirectory;
    }

    public void setDatabaseDirectory(String databaseDirectory) {
        this.databaseDirectory = databaseDirectory;
    }
    public String getDatabasePasswordFilename() {
        return databasePasswordFilename;
    }

    public void setDatabasePasswordFilename(String databasePasswordFilename) {
        this.databasePasswordFilename = databasePasswordFilename;
    }

    public String getPkcs12PasswordFilename() {
        return pkcs12PasswordFilename;
    }

    public void setPkcs12PasswordFilename(String pkcs12PasswordFilename) {
        this.pkcs12PasswordFilename = pkcs12PasswordFilename;
    }

    public String getPkcs12OutputFilename() {
        return pkcs12OutputFilename;
    }

    public void setPkcs12OutputFilename(String pkcs12OutputFilename) {
        this.pkcs12OutputFilename = pkcs12OutputFilename;
    }

    void debug(String s) {
        if (debug)
            System.out.println("PKCS12Export: " + s);
    }

    byte[] getEncodedKey(org.mozilla.jss.crypto.PrivateKey pkey) throws Exception {

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
        SymmetricKey sk = kg.generate();

        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        byte iv[] = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        IVParameterSpec param = new IVParameterSpec(iv);
        wrapper.initWrap(sk, param);
        byte[] enckey = wrapper.wrap(pkey);

        Cipher c = token.getCipherContext(EncryptionAlgorithm.DES3_CBC_PAD);
        c.initDecrypt(sk, param);
        return c.doFinal(enckey);
    }

    void addKeyBag(org.mozilla.jss.crypto.PrivateKey pkey, X509Certificate x509cert,
            Password pass, byte[] localKeyId, SEQUENCE safeContents) throws Exception {

        PasswordConverter passConverter = new PasswordConverter();
        byte salt[] = { 0x01, 0x01, 0x01, 0x01 };
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
    }

    byte[] addCertBag(X509Certificate x509cert, String nickname,
            SEQUENCE safeContents) throws Exception {

        ASN1Value cert = new OCTET_STRING(x509cert.getEncoded());
        byte[] localKeyId = createLocalKeyId(x509cert);

        SET certAttrs = null;
        if (nickname != null)
            certAttrs = createBagAttrs(nickname, localKeyId);

        SafeBag certBag = new SafeBag(SafeBag.CERT_BAG,
                new CertBag(CertBag.X509_CERT_TYPE, cert), certAttrs);

        safeContents.addElement(certBag);

        return localKeyId;
    }

    byte[] createLocalKeyId(X509Certificate cert) throws Exception {

        // SHA1 hash of the X509Cert der encoding
        byte certDer[] = cert.getEncoded();

        MessageDigest md = MessageDigest.getInstance("SHA");

        md.update(certDer);
        return md.digest();
    }

    SET createBagAttrs(String nickName, byte localKeyId[])
            throws Exception {

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
    }

    public byte[] generatePKCS12Data(Password password) throws Exception {

        debug("Generating PKCS #12 data");

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();
        CryptoStore store = token.getCryptoStore();

        X509Certificate[] certs = store.getCertificates();

        SEQUENCE encSafeContents = new SEQUENCE();
        SEQUENCE safeContents = new SEQUENCE();

        for (int i = 0; i < certs.length; i++) {
            String nickname = certs[i].getNickname();
            debug(" * Certificate: " + nickname);
            try {
                org.mozilla.jss.crypto.PrivateKey prikey = cm.findPrivKeyByCert(certs[i]);

                debug("   Private key exists");
                byte localKeyId[] =
                        addCertBag(certs[i], nickname, safeContents);
                addKeyBag(prikey, certs[i], password, localKeyId, encSafeContents);

            } catch (org.mozilla.jss.crypto.ObjectNotFoundException e) {
                debug("   Private key does not exist");
                addCertBag(certs[i], null, safeContents);
            }
        }

        AuthenticatedSafes authSafes = new AuthenticatedSafes();
        authSafes.addSafeContents(safeContents);
        authSafes.addSafeContents(encSafeContents);

        PFX pfx = new PFX(authSafes);
        pfx.computeMacData(password, null, 5);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        pfx.encode(bos);

        return bos.toByteArray();
    }

    public void initDatabase() throws Exception {

        debug("Initializing database in " + databaseDirectory);

        CryptoManager.InitializationValues vals =
                new CryptoManager.InitializationValues(
                        databaseDirectory, "", "", "secmod.db");
        CryptoManager.initialize(vals);

        CryptoManager cm = CryptoManager.getInstance();
        CryptoToken token = cm.getInternalKeyStorageToken();

        debug("Reading database password from " + databasePasswordFilename);

        String line;
        try (BufferedReader in = new BufferedReader(new FileReader(databasePasswordFilename))) {
            line = in.readLine();
            if (line == null) {
                line = "";
            }
        }
        Password password = new Password(line.toCharArray());

        debug("Logging into security token");

        try {
            token.login(password);
        } finally {
            password.clear();
        }
    }

    public void exportData() throws Exception {

        debug("Reading PKCS #12 password from " + pkcs12PasswordFilename);

        String line;
        try (BufferedReader in = new BufferedReader(new FileReader(pkcs12PasswordFilename))) {
            line = in.readLine();
            if (line == null) {
                line = "";
            }
        }
        Password password = new Password(line.toCharArray());

        byte[] data;
        try {
            data = generatePKCS12Data(password);
        } finally {
            password.clear();
        }

        debug("Storing PKCS #12 data into " + pkcs12OutputFilename);

        try (FileOutputStream fos = new FileOutputStream(pkcs12OutputFilename)) {
            fos.write(data);
        }
    }

    public static void printUsage() {
        System.out.println(
                "Usage: PKCS12Export -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
        System.out.println();
        System.out.println("If you want to turn on debug, do the following:");
        System.out.println(
                "Usage: PKCS12Export -debug -d <cert/key db directory> -p <file containing password for keydb> -w <file containing pkcs12 password> -o <output file for pkcs12>");
    }

    public static void main(String args[]) throws Exception {

        if (args.length < 8) {
            printUsage();
            System.exit(1);
        }

        boolean debug = false;
        String databaseDirectory = null;
        String databasePasswordFilename = null;
        String pkcs12PasswordFilename = null;
        String pkcs12OutputFilename = null;

        // TODO: get parameters using getopt

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-d")) {
                databaseDirectory = args[i + 1];

            } else if (args[i].equals("-p")) {
                databasePasswordFilename = args[i + 1];

            } else if (args[i].equals("-s")) {
                // snickname = args[i + 1];

            } else if (args[i].equals("-w")) {
                pkcs12PasswordFilename = args[i + 1];

            } else if (args[i].equals("-o")) {
                pkcs12OutputFilename = args[i + 1];

            } else if (args[i].equals("-debug")) {
                debug = true;
            }
        }

        // TODO: validate parameters

        try {
            PKCS12Export tool = new PKCS12Export();
            tool.setDebug(debug);
            tool.setDatabaseDirectory(databaseDirectory);
            tool.setDatabasePasswordFilename(databasePasswordFilename);
            tool.setPkcs12PasswordFilename(pkcs12PasswordFilename);
            tool.setPkcs12OutputFilename(pkcs12OutputFilename);

            tool.initDatabase();
            tool.exportData();

        } catch (Exception e) {
            if (debug) {
                e.printStackTrace();
            } else {
                System.err.println("ERROR: " + e);
            }
            System.exit(1);
        }
    }
}
