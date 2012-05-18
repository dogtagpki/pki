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
 * Subsystem certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
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

        extension.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.NON_REPUDIATION, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.valueOf(true));
        return extension;
    }
}
