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
import java.io.*;
import java.math.*;
import java.security.PrivateKey;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.*;
import java.security.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import org.mozilla.jss.crypto.Signature;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.CryptoManager.*;
import org.mozilla.jss.*;


/**
 * Subsystem certificate.
 * 
 * @author Christine Ho
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class SubsystemCert extends CertificateInfo {

    public SubsystemCert(KeyCertData properties) {
        this(properties, null);
    }

    public SubsystemCert(KeyCertData properties, KeyPair pair) {
        super(properties, pair);
        try {
            if (mProperties.get(Constants.PR_SSL_CLIENT_BIT) == null)
                mProperties.put(Constants.PR_SSL_CLIENT_BIT, Constants.TRUE);
        } catch (Exception e) {
            mProperties.put(Constants.PR_SSL_CLIENT_BIT, Constants.TRUE);
        }
    }

    public String getSubjectName() {
        return (String) mProperties.get(Constants.PR_SUBJECT_NAME);
    }

    public void updateConfig(IConfigStore cmsFileTmp) throws EBaseException {
    }

    public String getNickname() {
        String name = (String) mProperties.get(Constants.PR_NICKNAME);
        String instanceName = (String) mProperties.get(ConfigConstants.PR_CERT_INSTANCE_NAME);

        if (name != null)
            return name;
        return "subsystemCert " + instanceName;
    }

    public String getKeyAlgorithm() {
        return (String) mProperties.get(Constants.PR_KEY_TYPE);
    }

    protected KeyUsageExtension getKeyUsageExtension() throws IOException {
        KeyUsageExtension extension = new KeyUsageExtension();

        extension.set(KeyUsageExtension.DIGITAL_SIGNATURE, new Boolean(true));
        extension.set(KeyUsageExtension.NON_REPUDIATION, new Boolean(true));
        extension.set(KeyUsageExtension.KEY_ENCIPHERMENT, new Boolean(true));
        return extension;
    }
}

