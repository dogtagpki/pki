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


// package com.netscape.cmstools;

import org.mozilla.jss.pkix.cmc.*;
import org.mozilla.jss.pkix.cms.*;
import org.mozilla.jss.pkix.cert.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkcs10.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.*;
import org.mozilla.jss.*;

import sun.misc.BASE64Encoder;
import sun.misc.*;

import java.io.*;
import java.util.*;

import com.netscape.cmscore.shares.*;

public class RecoverPin {
    
    public static String getPassword(Hashtable shares) throws Exception
    {
        System.out.println("Share size '" + shares.size() + "'");
        JoinShares j = new JoinShares(shares.size());

        Enumeration e = shares.keys();
        while (e.hasMoreElements()) {
          String next = (String) e.nextElement();
System.out.println("Add share " + (int)(Integer.parseInt(next) + 1));
          j.addShare(Integer.parseInt(next) + 1,
                (byte[]) shares.get(next));
        }
        byte secret[] = j.recoverSecret();
        String pwd = new String(secret);
        return pwd;
    }

    public static byte[] resizeShare(byte share[]) {
        byte data[] = new byte[share.length - 2];

        for (int i = 2; i < share.length; i++) {
            data[i - 2] = share[i];
        }
        return data;
    }

    public static Hashtable getShares(CryptoToken token,
              Properties kra_mn_p) throws Exception
    {
        BufferedReader br = new BufferedReader( new InputStreamReader(System.in));
        Hashtable v = new Hashtable();
        Enumeration e = kra_mn_p.keys();
        int n = Integer.parseInt((String)kra_mn_p.get("n"));
        for (int i = 0; i < n; i++) {
          String uid = (String)kra_mn_p.get("uid"+i);
          System.out.println("Got uid '" + uid + "'");

          String encrypted = (String)kra_mn_p.get("share"+i);
          System.out.println("Got share '" + encrypted + "'");

          BASE64Decoder decoder = new BASE64Decoder();
          byte share[] = decoder.decodeBuffer(encrypted);
          System.out.println("Got encrypted share length '" + 
                  share.length + "'");

          System.out.println("Please input password for " + uid + ":");
          String pwd = br.readLine();
          System.out.println("Got password '" + pwd + "'");

          Cipher cipher = token.getCipherContext(
                    EncryptionAlgorithm.DES3_CBC_PAD);
          byte iv[] = {0x01, 0x01, 0x01, 0x01, 0x01,
                    0x01, 0x01, 0x01};
          Password pass = new Password(pwd.toCharArray());
          KeyGenerator kg = token.getKeyGenerator(
                        PBEAlgorithm.PBE_SHA1_DES3_CBC);
          PBEKeyGenParams kgp = new PBEKeyGenParams(pass,
                    iv, 5);
          kg.initialize(kgp);
          SymmetricKey sk = kg.generate();
          cipher.initDecrypt(sk, new IVParameterSpec(iv));
          byte dec[] = cipher.doFinal(share);
          System.out.println("Got decrypted share length '" + dec.length + "'");
          System.out.println("Got share[0] '" + dec[0] + "'");
          System.out.println("Got share[1] '" + dec[1] + "'");
          byte res[] = resizeShare(dec);
          v.put(Integer.toString(i), res);
        }
        return v;
    }

    public static void main(String args[]) throws Exception
    {
       if (args.length != 4) {
             System.out.println("Usage: RecoverPin <alias directory> <prefix> <password> <kra-mn.conf path>");
             System.exit(0);
        }

        String alias = args[0];
        String prefix = args[1];
        String password = args[2];
        String path_kra_mn = args[3];

        CryptoManager.InitializationValues vals = 
                 new CryptoManager.InitializationValues(alias,
                 prefix, prefix, "secmod.db");

        CryptoManager.initialize(vals);
        CryptoManager cm = CryptoManager.getInstance();

        // load files into properties
        Properties kra_mn_p = new Properties();
        kra_mn_p.load(new FileInputStream(path_kra_mn));

        CryptoToken token = cm.getInternalKeyStorageToken();
        token.login(new Password(password.toCharArray()));

        Hashtable shares = getShares(token, kra_mn_p);

        String pwd = getPassword(shares);
        System.out.println("=> Pin is '" + pwd + "'");
    }
}
