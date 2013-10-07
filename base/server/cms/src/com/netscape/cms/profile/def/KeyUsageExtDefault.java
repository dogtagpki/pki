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

import java.io.IOException;
import java.util.Locale;

import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a Key Usage extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class KeyUsageExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "keyUsageCritical";
    public static final String CONFIG_DIGITAL_SIGNATURE =
            "keyUsageDigitalSignature";
    public static final String CONFIG_NON_REPUDIATION =
            "keyUsageNonRepudiation";
    public static final String CONFIG_KEY_ENCIPHERMENT =
            "keyUsageKeyEncipherment";
    public static final String CONFIG_DATA_ENCIPHERMENT =
            "keyUsageDataEncipherment";
    public static final String CONFIG_KEY_AGREEMENT = "keyUsageKeyAgreement";
    public static final String CONFIG_KEY_CERTSIGN = "keyUsageKeyCertSign";
    public static final String CONFIG_CRL_SIGN = "keyUsageCrlSign";
    public static final String CONFIG_ENCIPHER_ONLY = "keyUsageEncipherOnly";
    public static final String CONFIG_DECIPHER_ONLY = "keyUsageDecipherOnly";

    public static final String VAL_CRITICAL = "keyUsageCritical";
    public static final String VAL_DIGITAL_SIGNATURE =
            "keyUsageDigitalSignature";
    public static final String VAL_NON_REPUDIATION =
            "keyUsageNonRepudiation";
    public static final String VAL_KEY_ENCIPHERMENT =
            "keyUsageKeyEncipherment";
    public static final String VAL_DATA_ENCIPHERMENT =
            "keyUsageDataEncipherment";
    public static final String VAL_KEY_AGREEMENT = "keyUsageKeyAgreement";
    public static final String VAL_KEY_CERTSIGN = "keyUsageKeyCertSign";
    public static final String VAL_CRL_SIGN = "keyUsageCrlSign";
    public static final String VAL_ENCIPHER_ONLY = "keyUsageEncipherOnly";
    public static final String VAL_DECIPHER_ONLY = "keyUsageDecipherOnly";

    public KeyUsageExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_DIGITAL_SIGNATURE);
        addValueName(VAL_NON_REPUDIATION);
        addValueName(VAL_KEY_ENCIPHERMENT);
        addValueName(VAL_DATA_ENCIPHERMENT);
        addValueName(VAL_KEY_AGREEMENT);
        addValueName(VAL_KEY_CERTSIGN);
        addValueName(VAL_CRL_SIGN);
        addValueName(VAL_ENCIPHER_ONLY);
        addValueName(VAL_DECIPHER_ONLY);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_DIGITAL_SIGNATURE);
        addConfigName(CONFIG_NON_REPUDIATION);
        addConfigName(CONFIG_KEY_ENCIPHERMENT);
        addConfigName(CONFIG_DATA_ENCIPHERMENT);
        addConfigName(CONFIG_KEY_AGREEMENT);
        addConfigName(CONFIG_KEY_CERTSIGN);
        addConfigName(CONFIG_CRL_SIGN);
        addConfigName(CONFIG_ENCIPHER_ONLY);
        addConfigName(CONFIG_DECIPHER_ONLY);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_DIGITAL_SIGNATURE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DIGITAL_SIGNATURE"));
        } else if (name.equals(CONFIG_NON_REPUDIATION)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NON_REPUDIATION"));
        } else if (name.equals(CONFIG_KEY_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_ENCIPHERMENT"));
        } else if (name.equals(CONFIG_DATA_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DATA_ENCIPHERMENT"));
        } else if (name.equals(CONFIG_KEY_AGREEMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_AGREEMENT"));
        } else if (name.equals(CONFIG_KEY_CERTSIGN)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_CERTSIGN"));
        } else if (name.equals(CONFIG_CRL_SIGN)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRL_SIGN"));
        } else if (name.equals(CONFIG_ENCIPHER_ONLY)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENCIPHER_ONLY"));
        } else if (name.equals(CONFIG_DECIPHER_ONLY)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DECIPHER_ONLY"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_DIGITAL_SIGNATURE)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DIGITAL_SIGNATURE"));
        } else if (name.equals(VAL_NON_REPUDIATION)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NON_REPUDIATION"));
        } else if (name.equals(VAL_KEY_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_ENCIPHERMENT"));
        } else if (name.equals(VAL_DATA_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DATA_ENCIPHERMENT"));
        } else if (name.equals(VAL_KEY_AGREEMENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_AGREEMENT"));
        } else if (name.equals(VAL_KEY_CERTSIGN)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_CERTSIGN"));
        } else if (name.equals(VAL_CRL_SIGN)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRL_SIGN"));
        } else if (name.equals(VAL_ENCIPHER_ONLY)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENCIPHER_ONLY"));
        } else if (name.equals(VAL_DECIPHER_ONLY)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DECIPHER_ONLY"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            KeyUsageExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);

            if (ext == null) {
                populate(null, info);

            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_DIGITAL_SIGNATURE)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.DIGITAL_SIGNATURE, val);
            } else if (name.equals(VAL_NON_REPUDIATION)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.NON_REPUDIATION, val);
            } else if (name.equals(VAL_KEY_ENCIPHERMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.KEY_ENCIPHERMENT, val);
            } else if (name.equals(VAL_DATA_ENCIPHERMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.DATA_ENCIPHERMENT, val);
            } else if (name.equals(VAL_KEY_AGREEMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.KEY_AGREEMENT, val);
            } else if (name.equals(VAL_KEY_CERTSIGN)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.KEY_CERTSIGN, val);
            } else if (name.equals(VAL_CRL_SIGN)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.CRL_SIGN, val);
            } else if (name.equals(VAL_ENCIPHER_ONLY)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.ENCIPHER_ONLY, val);
            } else if (name.equals(VAL_DECIPHER_ONLY)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(KeyUsageExtension.DECIPHER_ONLY, val);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(PKIXExtensions.KeyUsage_Id.toString(), ext, info);
        } catch (IOException e) {
            CMS.debug("KeyUsageExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        } catch (EProfileException e) {
            CMS.debug("KeyUsageExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        try {
            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            KeyUsageExtension ext = (KeyUsageExtension)
                    getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);

            if (ext == null) {
                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                if (ext.isCritical()) {
                    return "true";
                } else {
                    return "false";
                }
            } else if (name.equals(VAL_DIGITAL_SIGNATURE)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }

                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.DIGITAL_SIGNATURE);

                return val.toString();
            } else if (name.equals(VAL_NON_REPUDIATION)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.NON_REPUDIATION);

                return val.toString();
            } else if (name.equals(VAL_KEY_ENCIPHERMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.KEY_ENCIPHERMENT);

                return val.toString();
            } else if (name.equals(VAL_DATA_ENCIPHERMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.DATA_ENCIPHERMENT);

                return val.toString();
            } else if (name.equals(VAL_KEY_AGREEMENT)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.KEY_AGREEMENT);

                return val.toString();
            } else if (name.equals(VAL_KEY_CERTSIGN)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.KEY_CERTSIGN);

                return val.toString();
            } else if (name.equals(VAL_CRL_SIGN)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.CRL_SIGN);

                return val.toString();
            } else if (name.equals(VAL_ENCIPHER_ONLY)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.ENCIPHER_ONLY);

                return val.toString();
            } else if (name.equals(VAL_DECIPHER_ONLY)) {
                ext = (KeyUsageExtension)
                        getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean)
                        ext.get(KeyUsageExtension.DECIPHER_ONLY);

                return val.toString();
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (IOException e) {
            CMS.debug("KeyUsageExtDefault: getValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_DIGITAL_SIGNATURE),
                getConfig(CONFIG_NON_REPUDIATION),
                getConfig(CONFIG_KEY_ENCIPHERMENT),
                getConfig(CONFIG_DATA_ENCIPHERMENT),
                getConfig(CONFIG_KEY_AGREEMENT),
                getConfig(CONFIG_KEY_CERTSIGN),
                getConfig(CONFIG_CRL_SIGN),
                getConfig(CONFIG_ENCIPHER_ONLY),
                getConfig(CONFIG_DECIPHER_ONLY)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_KEY_USAGE_EXT", params);

    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        KeyUsageExtension ext = createKeyUsageExtension();

        addExtension(PKIXExtensions.KeyUsage_Id.toString(), ext, info);
    }

    public KeyUsageExtension createKeyUsageExtension() {
        KeyUsageExtension ext = null;
        boolean[] bits = new boolean[KeyUsageExtension.NBITS];

        boolean critical = getConfigBoolean(CONFIG_CRITICAL);

        bits[0] = getConfigBoolean(CONFIG_DIGITAL_SIGNATURE);
        bits[1] = getConfigBoolean(CONFIG_NON_REPUDIATION);
        bits[2] = getConfigBoolean(CONFIG_KEY_ENCIPHERMENT);
        bits[3] = getConfigBoolean(CONFIG_DATA_ENCIPHERMENT);
        bits[4] = getConfigBoolean(CONFIG_KEY_AGREEMENT);
        bits[5] = getConfigBoolean(CONFIG_KEY_CERTSIGN);
        bits[6] = getConfigBoolean(CONFIG_CRL_SIGN);
        bits[7] = getConfigBoolean(CONFIG_ENCIPHER_ONLY);
        bits[8] = getConfigBoolean(CONFIG_DECIPHER_ONLY);
        try {
            ext = new KeyUsageExtension(critical, bits);
        } catch (Exception e) {
            CMS.debug("KeyUsageExtDefault: createKeyUsageExtension " +
                    e.toString());
        }
        return ext;
    }
}
