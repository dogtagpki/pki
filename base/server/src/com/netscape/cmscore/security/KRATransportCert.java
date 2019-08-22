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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.cmsutil.crypto.CryptoUtil;

import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;

/**
 * KRA transport certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class KRATransportCert extends CertificateInfo {
    public static final String SUBJECT_NAME =
            "CN=Data Recovery Manager, O=Netscape Communications, C=US";

    public KRATransportCert(KeyCertData properties) {
        this(properties, null);
    }

    public KRATransportCert(KeyCertData properties, KeyPair pair) {
        super(properties, pair);
        mProperties.put(Constants.PR_AKI, Constants.TRUE);
    }

    public void updateConfig(IConfigStore cmsFileTmp) throws EBaseException {
        String tokenname = (String) mProperties.get(Constants.PR_TOKEN_NAME);
        String nickname = getNickname();

        if (CryptoUtil.isInternalToken(tokenname))
            cmsFileTmp.putString("kra.transportUnit.nickName", nickname);
        else
            cmsFileTmp.putString("kra.transportUnit.nickName", tokenname + ":" + nickname);
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
        return "kraTransportCert " + instanceName;
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

        extension.set(KeyUsageExtension.KEY_ENCIPHERMENT,Boolean.valueOf(true));
        return extension;
    }
}
