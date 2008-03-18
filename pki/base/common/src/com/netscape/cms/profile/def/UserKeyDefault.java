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
package com.netscape.cms.profile.def;


import java.io.*;
import java.math.*;
import java.util.*;
import com.netscape.cms.profile.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.apps.CMS;

import java.security.interfaces.DSAParams;
import netscape.security.x509.*;
import netscape.security.provider.*;


/**
 * This class implements an enrollment default policy
 * that populates a user supplied key
 * into the certificate template.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class UserKeyDefault extends EnrollDefault {

    public static final String VAL_KEY = "KEY";
    public static final String VAL_LEN = "LEN";
    public static final String VAL_TYPE = "TYPE";

    public UserKeyDefault() {
        super();
        addValueName(VAL_TYPE);
        addValueName(VAL_LEN);
        addValueName(VAL_KEY);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_KEY)) {
            return new Descriptor(IDescriptor.STRING, 
                    IDescriptor.READONLY, 
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY"));
        } else if (name.equals(VAL_LEN)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY, 
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_LEN"));
        } else if (name.equals(VAL_TYPE)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY, 
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
        X509CertInfo info, String value)
        throws EPropertyException {
        // this default rule is readonly
    }

    public String getValue(String name, Locale locale,
        X509CertInfo info)
        throws EPropertyException {
        if (name == null) { 
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_KEY)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            } 
            if (k == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            return toHexString(k.getKey());
        } else if (name.equals(VAL_LEN)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) { 
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            try {
                if (k.getAlgorithm().equals("RSA")) {
                    return Integer.toString(getRSAKeyLen(k));
                } else {
                    return Integer.toString(getDSAKeyLen(k));
                }
            } catch (Exception e) {
                CMS.debug("UserKeyDefault: getValue " + e.toString());
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } else if (name.equals(VAL_TYPE)) {
            CertificateX509Key ck = null;

            try {
                ck = (CertificateX509Key)
                        info.get(X509CertInfo.KEY);
            } catch (Exception e) {
                // nothing
            }
            X509Key k = null;

            try {
                k = (X509Key)
                        ck.get(CertificateX509Key.KEY);
            } catch (Exception e) {
                // nothing
            }
            if (k == null) { 
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_PROFILE_KEY_NOT_FOUND"));
            }
            return k.getAlgorithm() + " - " + 
                k.getAlgorithmId().getOID().toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_KEY");
    }

    public int getRSAKeyLen(X509Key key) throws Exception {
        X509Key newkey = null;

        try {
            newkey = new X509Key(AlgorithmId.get("RSA"),
                        key.getKey());
        } catch (Exception e) {
            CMS.debug("UserKeyDefault: getRSAKey " + e.toString());
            throw e;
        }
        RSAPublicKey rsaKey = new RSAPublicKey(newkey.getEncoded());

        return rsaKey.getKeySize();
    }

    public int getDSAKeyLen(X509Key key) throws Exception {
        // Check DSAKey parameters.
        // size refers to the p parameter.
        DSAPublicKey dsaKey = new DSAPublicKey(key.getEncoded());
        DSAParams keyParams = dsaKey.getParams();
        BigInteger p = keyParams.getP();
        int len = p.bitLength();

        return len;
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
        throws EProfileException {
        CertificateX509Key certKey = null;
        // authenticate the certificate key, and move
        // the key from request into x509 certinfo
        try {
            byte[] certKeyData = request.getExtDataInByteArray(IEnrollProfile.REQUEST_KEY);
            if (certKeyData != null) {
                certKey = new CertificateX509Key(
                        new ByteArrayInputStream(certKeyData));
            }
            info.set(X509CertInfo.KEY, certKey);
        } catch (Exception e) {
            CMS.debug("UserKeyDefault: populate " + e.toString());
        }
    }
}
