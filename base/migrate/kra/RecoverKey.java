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

public class RecoverKey {
    
    public static void main(String args[]) throws Exception
    {
       if (args.length != 6) {
             System.out.println("Usage: RecoverKey <alias directory> <prefix> <password> <pin> <nickname> <kra-key.db path>");
             System.exit(0);
        }

        String alias = args[0];
        String prefix = args[1];
        String password = args[2];
        String pin = args[3];
        String nickname = args[4];
        String db_path = args[5];

        CryptoManager.InitializationValues vals = 
                 new CryptoManager.InitializationValues(alias,
                 prefix, prefix, "secmod.db");

        CryptoManager.initialize(vals);
        CryptoManager cm = CryptoManager.getInstance();

        CryptoToken token = cm.getInternalKeyStorageToken();
        token.login(new Password(password.toCharArray()));

        // retrieve public key
        X509Certificate cert = cm.findCertByNickname(nickname);

        // retrieve encrypted private key material
        File priFile = new File(db_path);
        byte priData[] = new byte[(new Long(priFile.length())).intValue()];
        FileInputStream fi = new FileInputStream(priFile);
        fi.read(priData);
        fi.close();

        // recover private key
        Password pass = new Password(pin.toCharArray());
        KeyGenerator kg = token.getKeyGenerator(
                        PBEAlgorithm.PBE_SHA1_DES3_CBC);
        byte iv[] = {0x01, 0x01, 0x01, 0x01,
                 0x01, 0x01, 0x01, 0x01};
        PBEKeyGenParams kgp = new PBEKeyGenParams(pass,
                    iv, 5);

        pass.clear();
        kg.initialize(kgp);
        SymmetricKey sk = kg.generate();

        KeyWrapper wrapper = token.getKeyWrapper(KeyWrapAlgorithm.DES3_CBC_PAD);
        wrapper.initUnwrap(sk, new IVParameterSpec(iv));
        PrivateKey pk = wrapper.unwrapPrivate(priData,
                    PrivateKey.RSA, cert.getPublicKey());

        System.out.println("=> Private is '" + pk + "'");
    }
}
