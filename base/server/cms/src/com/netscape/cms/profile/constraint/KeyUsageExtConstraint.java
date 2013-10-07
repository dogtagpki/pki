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

import java.util.Locale;

import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.KeyUsageExtDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserExtensionDefault;

/**
 * This class implements the key usage extension constraint.
 * It checks if the key usage constraint in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class KeyUsageExtConstraint extends EnrollConstraint {

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

    public KeyUsageExtConstraint() {
        super();
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
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_DIGITAL_SIGNATURE)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DIGITAL_SIGNATURE"));
        } else if (name.equals(CONFIG_NON_REPUDIATION)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_NON_REPUDIATION"));
        } else if (name.equals(CONFIG_KEY_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_ENCIPHERMENT"));
        } else if (name.equals(CONFIG_DATA_ENCIPHERMENT)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DATA_ENCIPHERMENT"));
        } else if (name.equals(CONFIG_KEY_AGREEMENT)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_AGREEMENT"));
        } else if (name.equals(CONFIG_KEY_CERTSIGN)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_KEY_CERTSIGN"));
        } else if (name.equals(CONFIG_CRL_SIGN)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRL_SIGN"));
        } else if (name.equals(CONFIG_ENCIPHER_ONLY)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_ENCIPHER_ONLY"));
        } else if (name.equals(CONFIG_DECIPHER_ONLY)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_DECIPHER_ONLY"));
        }
        return null;
    }

    public boolean isSet(boolean bits[], int position) {
        if (bits.length <= position)
            return false;
        return bits[position];
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        KeyUsageExtension ext = (KeyUsageExtension)
                getExtension(PKIXExtensions.KeyUsage_Id.toString(), info);

        if (ext == null) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_EXTENSION_NOT_FOUND",
                            PKIXExtensions.KeyUsage_Id.toString()));
        }

        boolean[] bits = ext.getBits();
        String value = getConfig(CONFIG_CRITICAL);

        if (!isOptional(value)) {
            boolean critical = getBoolean(value);

            if (critical != ext.isCritical()) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_CRITICAL_NOT_MATCHED"));
            }
        }
        value = getConfig(CONFIG_DIGITAL_SIGNATURE);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 0)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_DIGITAL_SIGNATURE_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_NON_REPUDIATION);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 1)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_NON_REPUDIATION_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_KEY_ENCIPHERMENT);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 2)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_KEY_ENCIPHERMENT_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_DATA_ENCIPHERMENT);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 3)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_DATA_ENCIPHERMENT_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_KEY_AGREEMENT);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 4)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_KEY_AGREEMENT_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_KEY_CERTSIGN);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 5)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_KEY_CERTSIGN_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_CRL_SIGN);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 6)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_CRL_SIGN_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_ENCIPHER_ONLY);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 7)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_ENCIPHER_ONLY_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_DECIPHER_ONLY);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != isSet(bits, 8)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_DECIPHER_ONLY_NOT_MATCHED",
                                value));
            }
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

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_KEY_USAGE_EXT_TEXT", params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof KeyUsageExtDefault)
            return true;
        if (def instanceof UserExtensionDefault)
            return true;
        return false;
    }
}
