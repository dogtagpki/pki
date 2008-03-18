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
package com.netscape.cms.profile.constraint;


import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.cms.profile.common.*;
import com.netscape.cms.profile.def.*;

import netscape.security.x509.*;
import netscape.security.provider.*;
import java.security.interfaces.DSAParams;
import java.math.BigInteger;


/**
 * This constraint is to check the key type and
 * key length.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class KeyConstraint extends EnrollConstraint {

    public static final String CONFIG_KEY_TYPE = "keyType"; // (DSA, RSA)
    public static final String CONFIG_KEY_MIN_LEN = "keyMinLength";
    public static final String CONFIG_KEY_MAX_LEN = "keyMaxLength";

    public KeyConstraint() {
        super();
        addConfigName(CONFIG_KEY_TYPE);
        addConfigName(CONFIG_KEY_MIN_LEN);
        addConfigName(CONFIG_KEY_MAX_LEN);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) { 
        if (name.equals(CONFIG_KEY_TYPE)) {
            return new Descriptor(IDescriptor.CHOICE, "RSA,DSA,EC,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else if (name.equals(CONFIG_KEY_MIN_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "512",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_MIN_LEN"));
        } else if (name.equals(CONFIG_KEY_MAX_LEN)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "4096",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_MAX_LEN"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
        throws ERejectException { 
        try {
            CertificateX509Key infokey = (CertificateX509Key)
                info.get(X509CertInfo.KEY);
            X509Key key = (X509Key) infokey.get(CertificateX509Key.KEY); 
            String alg = key.getAlgorithmId().getName().toUpperCase();
            String value = getConfig(CONFIG_KEY_TYPE);

            if (!isOptional(value)) {
                if (!alg.equals(value)) {
                    throw new ERejectException(
                            CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_KEY_TYPE_NOT_MATCHED", 
                                value));
                }
            }

            int keySize = 0;

            if (alg.equals("RSA")) { 
                keySize = getRSAKeyLen(key);
            } else if (alg.equals("DSA")) { 
                keySize = getDSAKeyLen(key);
            } else if (alg.equals("EC")) { 
                keySize = getECKeyLen(key);
            } else {
                throw new ERejectException(	
                        CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_INVALID_KEY_TYPE",
                            alg));
            }
            value = getConfig(CONFIG_KEY_MIN_LEN);
            if (!isOptional(value)) {
                if (keySize < Integer.parseInt(value)) {
                    throw new ERejectException(
                            CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_KEY_MIN_LEN_NOT_MATCHED",
                                value));
                }
            }

            value = getConfig(CONFIG_KEY_MAX_LEN);
            if (!isOptional(value)) {
                if (keySize > Integer.parseInt(value)) {
                    throw new ERejectException(
                            CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_KEY_MAX_LEN_NOT_MATCHED",
                                value));
                }
            }
        } catch (Exception e) {
            if (e instanceof ERejectException) {
                throw (ERejectException) e;
            }
            CMS.debug("KeyConstraint: " + e.toString());
            throw new ERejectException(CMS.getUserMessage(
                        getLocale(request), "CMS_PROFILE_KEY_NOT_FOUND"));
        }
    }

    public int getECKeyLen(X509Key key) throws Exception {
        return 256; // XXX
    }

    public int getRSAKeyLen(X509Key key) throws Exception {
        X509Key newkey = null;

        try {
            newkey = new X509Key(AlgorithmId.get("RSA"),
                        key.getKey());
        } catch (Exception e) {
            CMS.debug("KeyConstraint: getRSAKey Len " + e.toString());
            return -1;
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

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_KEY_TYPE),
                getConfig(CONFIG_KEY_MIN_LEN),
                getConfig(CONFIG_KEY_MAX_LEN)
            };

        return CMS.getUserMessage(locale, 
                "CMS_PROFILE_CONSTRAINT_KEY_TEXT", params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UserKeyDefault)
            return true;
        return false;
    }
}
