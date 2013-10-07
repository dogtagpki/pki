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

import java.security.cert.CertificateException;
import java.util.Locale;

import netscape.security.extensions.NSCertTypeExtension;
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
 * that populates a Netscape Certificate Type extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class NSCertTypeExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "nsCertCritical";
    public static final String CONFIG_SSL_CLIENT = "nsCertSSLClient";
    public static final String CONFIG_SSL_SERVER = "nsCertSSLServer";
    public static final String CONFIG_EMAIL = "nsCertEmail";
    public static final String CONFIG_OBJECT_SIGNING = "nsCertObjectSigning";
    public static final String CONFIG_SSL_CA = "nsCertSSLCA";
    public static final String CONFIG_EMAIL_CA = "nsCertEmailCA";
    public static final String CONFIG_OBJECT_SIGNING_CA = "nsCertObjectSigningCA";

    public static final String VAL_CRITICAL = "nsCertCritical";
    public static final String VAL_SSL_CLIENT = "nsCertSSLClient";
    public static final String VAL_SSL_SERVER = "nsCertSSLServer";
    public static final String VAL_EMAIL = "nsCertEmail";
    public static final String VAL_OBJECT_SIGNING = "nsCertObjectSigning";
    public static final String VAL_SSL_CA = "nsCertSSLCA";
    public static final String VAL_EMAIL_CA = "nsCertEmailCA";
    public static final String VAL_OBJECT_SIGNING_CA = "nsCertObjectSigningCA";

    public NSCertTypeExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_SSL_CLIENT);
        addValueName(VAL_SSL_SERVER);
        addValueName(VAL_EMAIL);
        addValueName(VAL_OBJECT_SIGNING);
        addValueName(VAL_SSL_CA);
        addValueName(VAL_EMAIL_CA);
        addValueName(VAL_OBJECT_SIGNING_CA);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_SSL_CLIENT);
        addConfigName(CONFIG_SSL_SERVER);
        addConfigName(CONFIG_EMAIL);
        addConfigName(CONFIG_OBJECT_SIGNING);
        addConfigName(CONFIG_SSL_CA);
        addConfigName(CONFIG_EMAIL_CA);
        addConfigName(CONFIG_OBJECT_SIGNING_CA);
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
        } else if (name.equals(CONFIG_SSL_CLIENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CLIENT"));
        } else if (name.equals(CONFIG_SSL_SERVER)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_SERVER"));
        } else if (name.equals(CONFIG_EMAIL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL"));
        } else if (name.equals(CONFIG_OBJECT_SIGNING)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OBJECT_SIGNING"));
        } else if (name.equals(CONFIG_SSL_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CA"));
        } else if (name.equals(CONFIG_EMAIL_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL_CA"));
        } else if (name.equals(CONFIG_OBJECT_SIGNING_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OBJECT_SIGNING_CA"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_SSL_CLIENT)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CLIENT"));
        } else if (name.equals(VAL_SSL_SERVER)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_SERVER"));
        } else if (name.equals(VAL_EMAIL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL"));
        } else if (name.equals(VAL_OBJECT_SIGNING)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OBJECT_SIGNING"));
        } else if (name.equals(VAL_SSL_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CA"));
        } else if (name.equals(VAL_EMAIL_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL_CA"));
        } else if (name.equals(VAL_OBJECT_SIGNING_CA)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OBJECT_SIGNING_CA"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            NSCertTypeExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);

            if (ext == null) {
                populate(null, info);

            }
            if (name.equals(VAL_CRITICAL)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                boolean val = Boolean.valueOf(value).booleanValue();

                if (ext == null) {
                    return;
                }
                ext.setCritical(val);
            } else if (name.equals(VAL_SSL_CLIENT)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.SSL_CLIENT, val);
            } else if (name.equals(VAL_SSL_SERVER)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.SSL_SERVER, val);
            } else if (name.equals(VAL_EMAIL)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.EMAIL, val);
            } else if (name.equals(VAL_OBJECT_SIGNING)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.OBJECT_SIGNING, val);
            } else if (name.equals(VAL_SSL_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.SSL_CA, val);
            } else if (name.equals(VAL_EMAIL_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.EMAIL_CA, val);
            } else if (name.equals(VAL_OBJECT_SIGNING_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return;
                }
                Boolean val = Boolean.valueOf(value);

                ext.set(NSCertTypeExtension.OBJECT_SIGNING_CA, val);
            } else {
                throw new EPropertyException("Invalid name " + name);
            }
            replaceExtension(NSCertTypeExtension.CertType_Id.toString(), ext, info);
        } catch (CertificateException e) {
            CMS.debug("NSCertTypeExtDefault: setValue " + e.toString());
        } catch (EProfileException e) {
            CMS.debug("NSCertTypeExtDefault: setValue " + e.toString());
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

            NSCertTypeExtension ext = (NSCertTypeExtension)
                    getExtension(NSCertTypeExtension.CertType_Id.toString(), info);

            if (ext == null) {
                try {
                    populate(null, info);

                } catch (EProfileException e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }

            }
            if (name.equals(VAL_CRITICAL)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);

                if (ext == null) {
                    return null;
                }
                if (ext.isCritical()) {
                    return "true";
                } else {
                    return "false";
                }
            } else if (name.equals(VAL_SSL_CLIENT)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.SSL_CLIENT);

                return val.toString();
            } else if (name.equals(VAL_SSL_SERVER)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.SSL_SERVER);

                return val.toString();
            } else if (name.equals(VAL_EMAIL)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.EMAIL);

                return val.toString();
            } else if (name.equals(VAL_OBJECT_SIGNING)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.OBJECT_SIGNING);

                return val.toString();
            } else if (name.equals(VAL_SSL_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.SSL_CA);

                return val.toString();
            } else if (name.equals(VAL_EMAIL_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.EMAIL_CA);

                return val.toString();
            } else if (name.equals(VAL_OBJECT_SIGNING_CA)) {
                ext = (NSCertTypeExtension)
                        getExtension(NSCertTypeExtension.CertType_Id.toString(), info);
                if (ext == null) {
                    return null;
                }
                Boolean val = (Boolean) ext.get(NSCertTypeExtension.OBJECT_SIGNING_CA);

                return val.toString();
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (CertificateException e) {
            CMS.debug("NSCertTypeExtDefault: setValue " + e.toString());
        }
        return null;
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_SSL_CLIENT),
                getConfig(CONFIG_SSL_SERVER),
                getConfig(CONFIG_EMAIL),
                getConfig(CONFIG_OBJECT_SIGNING),
                getConfig(CONFIG_SSL_CA),
                getConfig(CONFIG_EMAIL_CA),
                getConfig(CONFIG_OBJECT_SIGNING_CA)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_NS_CERT_TYPE_EXT", params);

    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        NSCertTypeExtension ext = createExtension();

        addExtension(NSCertTypeExtension.CertType_Id.toString(), ext, info);
    }

    public NSCertTypeExtension createExtension() {
        NSCertTypeExtension ext = null;
        boolean[] bits = new boolean[NSCertTypeExtension.NBITS];

        boolean critical = getConfigBoolean(CONFIG_CRITICAL);

        bits[0] = getConfigBoolean(CONFIG_SSL_CLIENT);
        bits[1] = getConfigBoolean(CONFIG_SSL_SERVER);
        bits[2] = getConfigBoolean(CONFIG_EMAIL);
        bits[3] = getConfigBoolean(CONFIG_OBJECT_SIGNING);
        bits[4] = false;
        bits[5] = getConfigBoolean(CONFIG_SSL_CA);
        bits[6] = getConfigBoolean(CONFIG_EMAIL_CA);
        bits[7] = getConfigBoolean(CONFIG_OBJECT_SIGNING_CA);
        try {
            ext = new NSCertTypeExtension(critical, bits);
        } catch (Exception e) {
            CMS.debug("NSCertTypeExtDefault: createExtension " +
                    e.toString());
        }
        return ext;
    }
}
