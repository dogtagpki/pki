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

import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.util.Locale;
import java.util.Vector;

import netscape.security.provider.DSAPublicKey;
import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserKeyDefault;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This constraint is to check the key type and
 * key length.
 *
 * @version $Revision$, $Date$
 */

public class KeyConstraint extends EnrollConstraint {

    public static final String CONFIG_KEY_TYPE = "keyType"; // (EC, RSA)
    public static final String CONFIG_KEY_PARAMETERS = "keyParameters";

    private static String[] cfgECCurves = null;
    private static String keyType = "";
    private static String keyParams = "";

    public KeyConstraint() {
        super();
        addConfigName(CONFIG_KEY_TYPE);
        addConfigName(CONFIG_KEY_PARAMETERS);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);

        String ecNames = "";
        try {
            ecNames = CMS.getConfigStore().getString("keys.ecc.curve.list");
        } catch (Exception e) {
        }

        CMS.debug("KeyConstraint.init ecNames: " + ecNames);
        if (ecNames != null && ecNames.length() != 0) {
            cfgECCurves = ecNames.split(",");
        }
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_KEY_TYPE)) {
            return new Descriptor(IDescriptor.CHOICE, "-,RSA,EC",
                    "RSA",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_TYPE"));
        } else if (name.equals(CONFIG_KEY_PARAMETERS)) {
            return new Descriptor(IDescriptor.STRING, null, "",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_PARAMETERS"));
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
            String keyType = value;

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
                //EC key case.
            } else {
                throw new ERejectException(
                        CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_INVALID_KEY_TYPE",
                                alg));
            }

            value = getConfig(CONFIG_KEY_PARAMETERS);

            String[] keyParams = value.split(",");

            if (alg.equals("EC")) {
                if (!alg.equals(keyType) && !isOptional(keyType)) {
                    throw new ERejectException(
                            CMS.getUserMessage(
                                    getLocale(request),
                                    "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                                    value));
                }

                Vector<?> vect = CryptoUtil.getECKeyCurve(key);

                boolean curveFound = false;

                if (vect != null) {
                    CMS.debug("vect: " + vect.toString());

                    if (!isOptional(keyType)) {
                        //Check the curve parameters only if explicit ECC or not optional
                        for (int i = 0; i < keyParams.length; i++) {
                            String ecParam = keyParams[i];
                            CMS.debug("keyParams[i]: " + i + " param: " + ecParam);
                            if (vect.contains(ecParam)) {
                                curveFound = true;
                                CMS.debug("KeyConstraint.validate: EC key constrainst passed.");
                                break;
                            }
                        }
                    } else {
                        curveFound = true;
                    }
                }

                if (!curveFound) {
                    CMS.debug("KeyConstraint.validate: EC key constrainst failed.");
                    throw new ERejectException(
                            CMS.getUserMessage(
                                    getLocale(request),
                                    "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                                    value));
                }

            } else {
                if (!arrayContainsString(keyParams, Integer.toString(keySize))) {
                    throw new ERejectException(
                            CMS.getUserMessage(
                                    getLocale(request),
                                    "CMS_PROFILE_KEY_PARAMS_NOT_MATCHED",
                                    value));
                }
                CMS.debug("KeyConstraint.validate: RSA key contraints passed.");
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
                getConfig(CONFIG_KEY_PARAMETERS)
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

    public void setConfig(String name, String value)
            throws EPropertyException {

        CMS.debug("KeyConstraint.setConfig name: " + name + " value: " + value);
        //establish keyType, we don't know which order these params will arrive
        if (name.equals(CONFIG_KEY_TYPE)) {
            keyType = value;
            if (keyParams.equals(""))
                return;
        }

        //establish keyParams
        if (name.equals(CONFIG_KEY_PARAMETERS)) {
            CMS.debug("establish keyParams: " + value);
            keyParams = value;

            if (keyType.equals(""))
                return;
        }
        // All the params we need for validation have been collected,
        // we don't know which order they will show up
        if (keyType.length() > 0 && keyParams.length() > 0) {
            String[] params = keyParams.split(",");
            boolean isECCurve = false;
            int keySize = 0;

            for (int i = 0; i < params.length; i++) {
                if (keyType.equals("EC")) {
                    if (cfgECCurves == null) {
                        //Use the static array as a backup if the config values are not present.
                        isECCurve = arrayContainsString(CryptoUtil.getECcurves(), params[i]);
                    } else {
                        isECCurve = arrayContainsString(cfgECCurves, params[i]);
                    }
                    if (isECCurve == false) { //Not a valid EC curve throw exception.
                        keyType = "";
                        keyParams = "";
                        throw new EPropertyException(CMS.getUserMessage(
                                "CMS_INVALID_PROPERTY", name));
                    }
                } else {
                    try {
                        keySize = Integer.parseInt(params[i]);
                    } catch (Exception e) {
                        if (isOptional(keyType)) {
                            isECCurve = arrayContainsString(CryptoUtil.getECcurves(), params[i]);
                        }
                        keySize = 0;
                    }
                    if ((keySize <= 0) && (isECCurve == false)) {
                        keyType = "";
                        keyParams = "";
                        throw new EPropertyException(CMS.getUserMessage(
                                "CMS_INVALID_PROPERTY", name));
                    }
                }
            }
        }
        //Actually set the configuration in the profile
        super.setConfig(CONFIG_KEY_TYPE, keyType);
        super.setConfig(CONFIG_KEY_PARAMETERS, keyParams);

        //Reset the vars for next round.
        keyType = "";
        keyParams = "";
    }

    private boolean arrayContainsString(String[] array, String value) {

        if (array == null || value == null) {
            return false;
        }

        for (int i = 0; i < array.length; i++) {
            if (array[i].equals(value)) {
                return true;
            }
        }

        return false;
    }
}
