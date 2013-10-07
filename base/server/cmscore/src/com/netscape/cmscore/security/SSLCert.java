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

import java.io.IOException;
import java.security.KeyPair;

import netscape.security.x509.KeyUsageExtension;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.security.KeyCertData;

/**
 * SSL server certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class SSLCert extends CertificateInfo {
    public static final String SUBJECT_NAME =
            "CN=SSL, O=Netscape Communications, C=US";

    public SSLCert(KeyCertData properties) {
        this(properties, null);
    }

    public SSLCert(KeyCertData properties, KeyPair pair) {
        super(properties, pair);
        try {
            if (mProperties.get(Constants.PR_AKI) == null) {
                mProperties.put(Constants.PR_AKI, Constants.FALSE);
            }
        } catch (Exception e) {
            mProperties.put(Constants.PR_AKI, Constants.FALSE);
        }

        // 020598: The server bit has to be turned on. Otherwise, it might
        // crash jss.
        //mProperties.put(Constants.PR_SSL_SERVER_BIT, Constants.TRUE);
    }

    public void updateConfig(IConfigStore cmsFileTmp) throws EBaseException {
        String tokenname = (String) mProperties.get(Constants.PR_TOKEN_NAME);
        String nickname = getNickname();
        String fullNickname = "";

        if (tokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
            fullNickname = nickname;
        } else {
            fullNickname = tokenname + ":" + nickname;
        }
        cmsFileTmp.putString("agent.nickName", fullNickname);
        cmsFileTmp.putString("ee.nickName", fullNickname);
        cmsFileTmp.putString("radm.nickName", fullNickname);
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
        return "Server-Cert " + instanceName;
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

        extension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.NON_REPUDIATION, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.DATA_ENCIPHERMENT, Boolean.valueOf(true));
        return extension;
    }
}
