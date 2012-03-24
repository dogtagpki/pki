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

import java.io.*;
import java.net.*;
import java.math.*;
import java.util.*;
import java.security.*;

import org.mozilla.jss.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;
import org.mozilla.jss.pkcs7.ContentInfo;
import org.mozilla.jss.pkcs7.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.util.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.pkcs11.PK11Token;

import netscape.security.x509.*;

import com.netscape.cmsutil.ocsp.*;
import com.netscape.cmsutil.ocsp.Request;

/**
 * Tool used to test out signing a CRL
 *
 * <p>
 * @version $Revision$ Date: $
 */
public class TestCRLSigning
{
    public static void printUsage()
    {
      System.out.println("Command <dbdir> <numreovked> <keysize> <tokenname> <tokenpwd>");
    }

    public static void main(String args[]) throws Exception
    { 
        String dir = args[0];
        String num = args[1];
        String keysize = args[2];
        String tokenname = args[3];
        String tokenpwd = args[4];

        // initialize JSS
        CryptoManager cm = null;
        CryptoManager.InitializationValues vals =
            new CryptoManager.InitializationValues(dir, "", "", "secmod.db");
        CryptoManager.initialize(vals);
        cm = CryptoManager.getInstance();

        // Login to token 
        CryptoToken token = null;
        if (tokenname.equals("internal")) {
          token = cm.getInternalKeyStorageToken();
        } else {
          token = cm.getTokenByName(tokenname);
        }
        Password pass = new Password(tokenpwd.toCharArray()); 
        token.login(pass);

        // generate key pair
        KeyPairGenerator g = token.getKeyPairGenerator(KeyPairAlgorithm.RSA);
        g.initialize(Integer.parseInt(keysize));
        KeyPair pair = g.genKeyPair();

        // generate revoked certificates
        long startPutting = System.currentTimeMillis();
        Date curDate = new Date();
        Hashtable badCerts = new Hashtable();
        int n = Integer.parseInt(num);
        for (int i = 0; i < n; i++) {
               badCerts.put(Integer.toString(i), 
            new RevokedCertImpl(new BigInteger(Integer.toString(i)), curDate));
        }
        long endPutting = System.currentTimeMillis();

        long startConstructing = System.currentTimeMillis();
        X509CRLImpl crl = new X509CRLImpl( 
                               new X500Name("CN=Signer"),
                               null,
                               curDate,
                               curDate,
                               badCerts,
                               null);
        long endConstructing = System.currentTimeMillis();


        System.out.println("Start signing");
        long startSigning = System.currentTimeMillis();
        crl.sign(pair.getPrivate(), "SHA1withRSA");
        long endSigning = System.currentTimeMillis();
        System.out.println("Done signing");

        long startData = System.currentTimeMillis();
        byte data[] = crl.getTBSCertList();
        long endData = System.currentTimeMillis();

        System.out.println("Summary:");
        System.out.println("Insertion time (ms): " + Long.toString(endPutting - startPutting));
        System.out.println("Construction time (ms): " + Long.toString(endConstructing - startConstructing));
        System.out.println("Signing time (ms): " + Long.toString(endSigning - startSigning));
        System.out.println("Data time (ms): " + Long.toString(endData - startData));
        System.out.println("Data size (bytes): " + Long.toString(data.length));
    }
}
