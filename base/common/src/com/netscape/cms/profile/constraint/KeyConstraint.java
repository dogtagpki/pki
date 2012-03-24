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
import java.util.HashMap;
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

/**
 * This constraint is to check the key type and
 * key length.
 * 
 * @version $Revision$, $Date$
 */
@SuppressWarnings("serial")
public class KeyConstraint extends EnrollConstraint {

    public static final String CONFIG_KEY_TYPE = "keyType"; // (EC, RSA)
    public static final String CONFIG_KEY_PARAMETERS = "keyParameters";

    private static final String[] ecCurves = {
            "nistp256", "nistp384", "nistp521", "sect163k1", "nistk163", "sect163r1", "sect163r2",
            "nistb163", "sect193r1", "sect193r2", "sect233k1", "nistk233", "sect233r1", "nistb233", "sect239k1",
            "sect283k1", "nistk283",
            "sect283r1", "nistb283", "sect409k1", "nistk409", "sect409r1", "nistb409", "sect571k1", "nistk571",
            "sect571r1", "nistb571",
            "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "nistp192", "secp224k1", "secp224r1",
            "nistp224", "secp256k1",
            "secp256r1", "secp384r1", "secp521r1", "prime192v1", "prime192v2", "prime192v3", "prime239v1",
            "prime239v2", "prime239v3", "c2pnb163v1",
            "c2pnb163v2", "c2pnb163v3", "c2pnb176v1", "c2tnb191v1", "c2tnb191v2", "c2tnb191v3", "c2pnb208w1",
            "c2tnb239v1", "c2tnb239v2", "c2tnb239v3",
            "c2pnb272w1", "c2pnb304w1", "c2tnb359w1", "c2pnb368w1", "c2tnb431r1", "secp112r1", "secp112r2",
            "secp128r1", "secp128r2", "sect113r1", "sect113r2",
            "sect131r1", "sect131r2"
    };

    private final static HashMap<String, Vector<String>> ecOIDs = new HashMap<String, Vector<String>>();
    static {
        ecOIDs.put("1.2.840.10045.3.1.7", new Vector<String>() {
            {
                add("nistp256");
                add("secp256r1");
            }
        });
        ecOIDs.put("1.3.132.0.34", new Vector<String>() {
            {
                add("nistp384");
                add("secp384r1");
            }
        });
        ecOIDs.put("1.3.132.0.35", new Vector<String>() {
            {
                add("nistp521");
                add("secp521r1");
            }
        });
        ecOIDs.put("1.3.132.0.1", new Vector<String>() {
            {
                add("sect163k1");
                add("nistk163");
            }
        });
        ecOIDs.put("1.3.132.0.2", new Vector<String>() {
            {
                add("sect163r1");
            }
        });
        ecOIDs.put("1.3.132.0.15", new Vector<String>() {
            {
                add("sect163r2");
                add("nistb163");
            }
        });
        ecOIDs.put("1.3.132.0.24", new Vector<String>() {
            {
                add("sect193r1");
            }
        });
        ecOIDs.put("1.3.132.0.25", new Vector<String>() {
            {
                add("sect193r2");
            }
        });
        ecOIDs.put("1.3.132.0.26", new Vector<String>() {
            {
                add("sect233k1");
                add("nistk233");
            }
        });
        ecOIDs.put("1.3.132.0.27", new Vector<String>() {
            {
                add("sect233r1");
                add("nistb233");
            }
        });
        ecOIDs.put("1.3.132.0.3", new Vector<String>() {
            {
                add("sect239k1");
            }
        });
        ecOIDs.put("1.3.132.0.16", new Vector<String>() {
            {
                add("sect283k1");
                add("nistk283");
            }
        });
        ecOIDs.put("1.3.132.0.17", new Vector<String>() {
            {
                add("sect283r1");
                add("nistb283");
            }
        });
        ecOIDs.put("1.3.132.0.36", new Vector<String>() {
            {
                add("sect409k1");
                add("nistk409");
            }
        });
        ecOIDs.put("1.3.132.0.37", new Vector<String>() {
            {
                add("sect409r1");
                add("nistb409");
            }
        });
        ecOIDs.put("1.3.132.0.38", new Vector<String>() {
            {
                add("sect571k1");
                add("nistk571");
            }
        });
        ecOIDs.put("1.3.132.0.39", new Vector<String>() {
            {
                add("sect571r1");
                add("nistb571");
            }
        });
        ecOIDs.put("1.3.132.0.9", new Vector<String>() {
            {
                add("secp160k1");
            }
        });
        ecOIDs.put("1.3.132.0.8", new Vector<String>() {
            {
                add("secp160r1");
            }
        });
        ecOIDs.put("1.3.132.0.30", new Vector<String>() {
            {
                add("secp160r2");
            }
        });
        ecOIDs.put("1.3.132.0.31", new Vector<String>() {
            {
                add("secp192k1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.1", new Vector<String>() {
            {
                add("secp192r1");
                add("nistp192");
                add("prime192v1");
            }
        });
        ecOIDs.put("1.3.132.0.32", new Vector<String>() {
            {
                add("secp224k1");
            }
        });
        ecOIDs.put("1.3.132.0.33", new Vector<String>() {
            {
                add("secp224r1");
                add("nistp224");
            }
        });
        ecOIDs.put("1.3.132.0.10", new Vector<String>() {
            {
                add("secp256k1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.2", new Vector<String>() {
            {
                add("prime192v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.3", new Vector<String>() {
            {
                add("prime192v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.4", new Vector<String>() {
            {
                add("prime239v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.5", new Vector<String>() {
            {
                add("prime239v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.1.6", new Vector<String>() {
            {
                add("prime239v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.1", new Vector<String>() {
            {
                add("c2pnb163v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.2", new Vector<String>() {
            {
                add("c2pnb163v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.3", new Vector<String>() {
            {
                add("c2pnb163v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.4", new Vector<String>() {
            {
                add("c2pnb176v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.5", new Vector<String>() {
            {
                add("c2tnb191v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.6", new Vector<String>() {
            {
                add("c2tnb191v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.7", new Vector<String>() {
            {
                add("c2tnb191v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.10", new Vector<String>() {
            {
                add("c2pnb208w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.11", new Vector<String>() {
            {
                add("c2tnb239v1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.12", new Vector<String>() {
            {
                add("c2tnb239v2");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.13", new Vector<String>() {
            {
                add("c2tnb239v3");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.16", new Vector<String>() {
            {
                add("c2pnb272w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.17", new Vector<String>() {
            {
                add("c2pnb304w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.19", new Vector<String>() {
            {
                add("c2pnb368w1");
            }
        });
        ecOIDs.put("1.2.840.10045.3.0.20", new Vector<String>() {
            {
                add("c2tnb431r1");
            }
        });
        ecOIDs.put("1.3.132.0.6", new Vector<String>() {
            {
                add("secp112r1");
            }
        });
        ecOIDs.put("1.3.132.0.7", new Vector<String>() {
            {
                add("secp112r2");
            }
        });
        ecOIDs.put("1.3.132.0.28", new Vector<String>() {
            {
                add("secp128r1");
            }
        });
        ecOIDs.put("1.3.132.0.29", new Vector<String>() {
            {
                add("secp128r2");
            }
        });
        ecOIDs.put("1.3.132.0.4", new Vector<String>() {
            {
                add("sect113r1");
            }
        });
        ecOIDs.put("1.3.132.0.5", new Vector<String>() {
            {
                add("sect113r2");
            }
        });
        ecOIDs.put("1.3.132.0.22", new Vector<String>() {
            {
                add("sect131r1");
            }
        });
        ecOIDs.put("1.3.132.0.23", new Vector<String>() {
            {
                add("sect131r2");
            }
        });
    }

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

                AlgorithmId algid = key.getAlgorithmId();

                CMS.debug("algId: " + algid);

                //Get raw string representation of alg parameters, will give 
                //us the curve OID.

                String params = null;
                if (algid != null) {
                    params = algid.getParametersString();
                }

                if (params.startsWith("OID.")) {
                    params = params.substring(4);
                }

                CMS.debug("EC key OID: " + params);
                Vector<String> vect = ecOIDs.get(params);

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
                        isECCurve = arrayContainsString(ecCurves, params[i]);
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
                        keySize = 0;
                    }
                    if (keySize <= 0) {
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
