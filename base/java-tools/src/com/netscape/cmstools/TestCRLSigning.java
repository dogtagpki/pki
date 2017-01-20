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

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.Hashtable;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairAlgorithm;
import org.mozilla.jss.crypto.KeyPairGenerator;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.RevokedCertificate;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CRLImpl;

/**
 * Tool used to test out signing a CRL
 *
 * <p>
 *
 * @version $Revision$ Date: $
 */
public class TestCRLSigning {
    public static void printUsage() {
        System.out.println("Command <dbdir> <numreovked> <keysize> <tokenname> <tokenpwd>");
    }

    public static void main(String args[]) throws Exception {
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
        if (CryptoUtil.isInternalToken(tokenname)) {
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
        Hashtable<BigInteger, RevokedCertificate> badCerts = new Hashtable<BigInteger, RevokedCertificate>();
        int n = Integer.parseInt(num);
        for (int i = 0; i < n; i++) {
            badCerts.put(new BigInteger(Integer.toString(i)),
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
