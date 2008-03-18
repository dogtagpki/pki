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
package com.netscape.cmscore.security;


import netscape.security.x509.*;
import netscape.security.util.*;
import java.util.*;
import java.security.PrivateKey;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.*;
import java.io.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.base.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.CryptoManager.*;
import org.mozilla.jss.crypto.*;
import java.security.cert.*;


/**
 * RA signing certificate 
 * 
 * @author Christine Ho
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class RASigningCert extends CertificateInfo {
    public static final String SUBJECT_NAME = 
        "CN=Registration Authority, O=Netscape Communications, C=US";
    private String mTokenname = Constants.PR_INTERNAL_TOKEN_NAME;

    public RASigningCert(KeyCertData properties) {
        this(properties, null);
    }

    public RASigningCert(KeyCertData properties, KeyPair pair) {
        super(properties, pair);
        String tmp = (String) mProperties.get(Constants.PR_TOKEN_NAME);

        if ((tmp != null) && 
            (!tmp.equals(Constants.PR_INTERNAL_TOKEN)))   
            mTokenname = tmp;
        try {
            if (mProperties.get(Constants.PR_AKI) == null) {
                mProperties.put(Constants.PR_AKI, Constants.FALSE);
            }
        } catch (Exception e) {
            mProperties.put(Constants.PR_AKI, Constants.FALSE);
        }
    }

    public void updateConfig(IConfigStore cmsFileTmp) throws EBaseException {
        String tokenname = (String) mProperties.get(Constants.PR_TOKEN_NAME);
        String nickname = getNickname();

        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME))
            cmsFileTmp.putString("ra.certNickname", nickname);
        else
            cmsFileTmp.putString("ra.certNickname", tokenname + ":" + nickname);
        cmsFileTmp.commit(false);
    }

    public String getSubjectName() {
        return (String) mProperties.get(Constants.PR_SUBJECT_NAME);
    }

    public String getNickname() {
        String name = (String) mProperties.get(Constants.PR_NICKNAME);
        String instanceName =
            (String) mProperties.get(ConfigConstants.PR_CERT_INSTANCE_NAME);

        if (name != null)
            return name;
        return "raSigningCert " + instanceName;
    }

    /*
     public SignatureAlgorithm getSigningAlgorithm() {
     SignatureAlgorithm sAlg =
     (SignatureAlgorithm)mProperties.get(Constants.PR_SIGNATURE_ALGORITHM);
     if (sAlg != null) {
     return sAlg;
     }
     String alg = (String)mProperties.get(Constants.PR_KEY_TYPE);
     
     if (alg.equals("RSA"))
     return SignatureAlgorithm.RSASignatureWithMD5Digest;
     else
     return SignatureAlgorithm.DSASignatureWithSHA1Digest;
     }
     */

    public String getKeyAlgorithm() {
        return (String) mProperties.get(Constants.PR_KEY_TYPE);
    }

    protected KeyUsageExtension getKeyUsageExtension() throws IOException {
        KeyUsageExtension extension = new KeyUsageExtension();

        extension.set(KeyUsageExtension.DIGITAL_SIGNATURE, new Boolean(true));
        return extension;
    }
}

