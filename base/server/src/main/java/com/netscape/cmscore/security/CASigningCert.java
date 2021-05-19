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
import java.math.BigInteger;
import java.security.KeyPair;

import org.mozilla.jss.crypto.PQGParamGenException;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.security.KeyCertData;

/**
 * CA signing certificate.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CASigningCert extends CertificateInfo {

    public static final String SUBJECT_NAME =
            "CN=Certificate Authority, O=Netscape Communications, C=US";

    public CASigningCert(KeyCertData properties) {
        this(properties, null);
    }

    public CASigningCert(KeyCertData properties, KeyPair pair) {
        super(properties, pair);
        /* included in console UI
        try {
            if (mProperties.get(Constants.PR_AKI) == null) {
                mProperties.put(Constants.PR_AKI, Constants.FALSE);
            }
        } catch (Exception e) {
            mProperties.put(Constants.PR_AKI, Constants.FALSE);
        }
        */
        try {
            if (mProperties.get(Constants.PR_CERT_LEN) == null) {
                mProperties.put(Constants.PR_CERT_LEN, "-1");
            }
        } catch (Exception e) {
            mProperties.put(Constants.PR_CERT_LEN, "-1");
        }
        try {
            if (mProperties.get(Constants.PR_IS_CA) == null) {
                // "null" mean no BasicConstriant
                mProperties.put(Constants.PR_IS_CA, "null");
            }
        } catch (Exception e) {
            // "null" mean no BasicConstriant
            mProperties.put(Constants.PR_IS_CA, "null");
        }
        /* included in console UI
        try {
            if (mProperties.get(Constants.PR_SKI) == null) {
                mProperties.put(Constants.PR_SKI, Constants.FALSE);
            }
        } catch (Exception e) {
            mProperties.put(Constants.PR_SKI, Constants.FALSE);
        }
        */
    }

    @Override
    public String getSubjectName() {
        return (String) mProperties.get(Constants.PR_SUBJECT_NAME);
    }

    // get PQG params from the configuration file
    public PQGParams getPQGParams() throws EBaseException, IOException, PQGParamGenException {

        byte[] p = mConfig.getByteArray("ca.dsaP", null);
        byte[] q = mConfig.getByteArray("ca.dsaQ", null);
        byte[] g = mConfig.getByteArray("ca.dsaG", null);
        byte[] seed = mConfig.getByteArray("ca.dsaSeed", null);
        byte[] H = mConfig.getByteArray("ca.dsaH", null);
        int counter = mConfig.getInteger("ca.dsaCounter", 0);

        if (p != null && q != null && g != null) {
            BigInteger P = new BigInteger(p);
            BigInteger Q = new BigInteger(q);
            BigInteger G = new BigInteger(g);
            BigInteger pqgSeed = new BigInteger(seed);
            BigInteger pqgH = new BigInteger(H);

            return new PQGParams(P, Q, G, pqgSeed, counter, pqgH);
        }
        return null;
    }

    @Override
    public String getNickname() {
        String name = (String) mProperties.get(Constants.PR_NICKNAME);
        String instanceName = (String) mProperties.get(ConfigConstants.PR_CERT_INSTANCE_NAME);

        if (name != null)
            return name;
        return "caSigningCert " + instanceName;
    }

    @Override
    public String getKeyAlgorithm() {
        return (String) mProperties.get(Constants.PR_KEY_TYPE);
    }

    @Override
    protected KeyUsageExtension getKeyUsageExtension() throws IOException {
        KeyUsageExtension extension = new KeyUsageExtension();

        extension.set(KeyUsageExtension.DIGITAL_SIGNATURE,Boolean.valueOf(true));
        extension.set(KeyUsageExtension.NON_REPUDIATION, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.KEY_CERTSIGN, Boolean.valueOf(true));
        extension.set(KeyUsageExtension.CRL_SIGN, Boolean.valueOf(true));
        return extension;
    }
}
