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

import java.math.BigInteger;
import java.util.Locale;

import netscape.security.extensions.InhibitAnyPolicyExtension;
import netscape.security.util.BigInt;
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
 * This class implements an inhibit Any-Policy extension
 *
 * @version $Revision$, $Date$
 */
public class InhibitAnyPolicyExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "critical";
    public static final String CONFIG_SKIP_CERTS = "skipCerts";

    public static final String VAL_CRITICAL = "critical";
    public static final String VAL_SKIP_CERTS = "skipCerts";

    private static final String SKIP_CERTS = "Skip Certs";

    public InhibitAnyPolicyExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_SKIP_CERTS);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_SKIP_CERTS);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.startsWith(CONFIG_SKIP_CERTS)) {
            return new Descriptor(IDescriptor.INTEGER, null, "0",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SKIP_CERTS"));
        } else {
            return null;
        }
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_SKIP_CERTS)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_SKIP_CERTS));
            }
        }
        super.setConfig(name, value);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "true",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_SKIP_CERTS)) {
            return new Descriptor(IDescriptor.INTEGER, null, "0",
                    CMS.getUserMessage(locale, "CMS_PROFILE_SKIP_CERTS"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            InhibitAnyPolicyExtension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ext = (InhibitAnyPolicyExtension)
                    getExtension(InhibitAnyPolicyExtension.OID, info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext = (InhibitAnyPolicyExtension)
                        getExtension(InhibitAnyPolicyExtension.OID, info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                boolean critical = Boolean.valueOf(value).booleanValue();

                ext.setCritical(critical);
            } else if (name.equals(VAL_SKIP_CERTS)) {
                ext = (InhibitAnyPolicyExtension)
                        getExtension(InhibitAnyPolicyExtension.OID, info);

                if (ext == null) {
                    // it is ok, the extension is never populated or delted
                    return;
                }
                boolean critical = ext.isCritical();
                if (value.equals("")) {
                    // if value is empty, do not add this extension
                    deleteExtension(InhibitAnyPolicyExtension.OID, info);
                    return;
                }
                BigInt num = null;
                try {
                    BigInteger l = new BigInteger(value);
                    num = new BigInt(l);
                } catch (Exception e) {
                    throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
                }
                ext = new InhibitAnyPolicyExtension(critical,
                        num);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
            replaceExtension(InhibitAnyPolicyExtension.OID, ext, info);
        } catch (EProfileException e) {
            CMS.debug("InhibitAnyPolicyExtDefault: setValue " + e.toString());
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                    locale, "CMS_INVALID_PROPERTY", name));
        }

        InhibitAnyPolicyExtension ext =
                (InhibitAnyPolicyExtension)
                getExtension(InhibitAnyPolicyExtension.OID, info);

        if (ext == null) {
            try {
                populate(null, info);
            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }
        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (InhibitAnyPolicyExtension)
                    getExtension(InhibitAnyPolicyExtension.OID, info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_SKIP_CERTS)) {
            ext = (InhibitAnyPolicyExtension)
                    getExtension(InhibitAnyPolicyExtension.OID, info);
            if (ext == null) {
                return null;
            }

            BigInt n = ext.getSkipCerts();
            return "" + n.toInt();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                    locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    /*
     * returns text that goes into description for this extension on
     * a profile
     */
    public String getText(Locale locale) {
        StringBuffer sb = new StringBuffer();
        sb.append(SKIP_CERTS + ":");
        sb.append(getConfig(CONFIG_SKIP_CERTS));

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_DEF_INHIBIT_ANY_POLICY_EXT",
                getConfig(CONFIG_CRITICAL), sb.toString());
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        InhibitAnyPolicyExtension ext = null;

        ext = createExtension(request);
        addExtension(InhibitAnyPolicyExtension.OID, ext, info);
    }

    public InhibitAnyPolicyExtension createExtension(IRequest request)
            throws EProfileException {
        InhibitAnyPolicyExtension ext = null;

        boolean critical = Boolean.valueOf(
                getConfig(CONFIG_CRITICAL)).booleanValue();

        String str = getConfig(CONFIG_SKIP_CERTS);
        if (str == null || str.equals("")) {
            ext = new InhibitAnyPolicyExtension();
            ext.setCritical(critical);
        } else {
            BigInt val = null;
            try {
                BigInteger b = new BigInteger(str);
                val = new BigInt(b);
            } catch (NumberFormatException e) {
                throw new EProfileException(
                        CMS.getUserMessage("CMS_PROFILE_INHIBIT_ANY_POLICY_WRONG_SKIP_CERTS"));
            }

            try {
                ext = new InhibitAnyPolicyExtension(critical, val);
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        }

        return ext;
    }
}
