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

import netscape.security.extensions.NSCertTypeExtension;
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
import com.netscape.cms.profile.def.NSCertTypeExtDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserExtensionDefault;

/**
 * This class implements the Netscape certificate type extension constraint.
 * It checks if the Netscape certificate type extension in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class NSCertTypeExtConstraint extends EnrollConstraint {

    public static final String CONFIG_CRITICAL = "nsCertCritical";
    public static final String CONFIG_SSL_CLIENT = "nsCertSSLClient";
    public static final String CONFIG_SSL_SERVER = "nsCertSSLServer";
    public static final String CONFIG_EMAIL = "nsCertEmail";
    public static final String CONFIG_OBJECT_SIGNING = "nsCertObjectSigning";
    public static final String CONFIG_SSL_CA = "nsCertSSLCA";
    public static final String CONFIG_EMAIL_CA = "nsCertEmailCA";
    public static final String CONFIG_OBJECT_SIGNING_CA = "nsCertObjectSigningCA";

    public NSCertTypeExtConstraint() {
        super();
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
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(CONFIG_SSL_CLIENT)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CLIENT"));
        } else if (name.equals(CONFIG_SSL_SERVER)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_SERVER"));
        } else if (name.equals(CONFIG_EMAIL)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL"));
        } else if (name.equals(CONFIG_OBJECT_SIGNING)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OBJECT_SIGNING"));
        } else if (name.equals(CONFIG_SSL_CA)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SSL_CA"));
        } else if (name.equals(CONFIG_EMAIL_CA)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EMAIL_CA"));
        } else if (name.equals(CONFIG_OBJECT_SIGNING_CA)) {
            return new Descriptor(IDescriptor.CHOICE, "true,false,-",
                    "-",
                    CMS.getUserMessage(locale,
                            "CMS_PROFILE_OBJECT_SIGNING_CA"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        NSCertTypeExtension ext = (NSCertTypeExtension)
                getExtension(NSCertTypeExtension.CertType_Id.toString(), info);

        if (ext == null) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_EXTENSION_NOT_FOUND",
                            NSCertTypeExtension.CertType_Id.toString()));
        }

        String value = getConfig(CONFIG_CRITICAL);

        if (!isOptional(value)) {
            boolean critical = getBoolean(value);

            if (critical != ext.isCritical()) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_CRITICAL_NOT_MATCHED"));
            }
        }
        value = getConfig(CONFIG_SSL_CLIENT);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(0)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_SSL_CLIENT_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_SSL_SERVER);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(1)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_SSL_SERVER_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_EMAIL);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(2)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_EMAIL_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_OBJECT_SIGNING);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(3)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_OBJECT_SIGNING_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_SSL_CA);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(4)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_SSL_CA_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_EMAIL_CA);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(5)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_EMAIL_CA_NOT_MATCHED",
                                value));
            }
        }
        value = getConfig(CONFIG_OBJECT_SIGNING_CA);
        if (!isOptional(value)) {
            boolean bit = getBoolean(value);

            if (bit != ext.isSet(6)) {
                throw new ERejectException(
                        CMS.getUserMessage(getLocale(request),
                                "CMS_PROFILE_OBJECT_SIGNING_CA_NOT_MATCHED",
                                value));
            }
        }
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

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_NS_CERT_EXT_TEXT", params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof NSCertTypeExtDefault)
            return true;
        if (def instanceof UserExtensionDefault)
            return true;
        return false;
    }
}
