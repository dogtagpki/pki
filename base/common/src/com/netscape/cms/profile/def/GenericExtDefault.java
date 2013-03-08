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

import java.util.Locale;

import netscape.security.util.DerOutputStream;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.Extension;
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
 * that populates a Netscape comment extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class GenericExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "genericExtCritical";
    public static final String CONFIG_OID = "genericExtOID";
    public static final String CONFIG_DATA = "genericExtData";

    public static final String VAL_CRITICAL = "genericExtCritical";
    public static final String VAL_DATA = "genericExtData";

    public GenericExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_DATA);

        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_OID);
        addConfigName(CONFIG_DATA);
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
        } else if (name.equals(CONFIG_OID)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "Comment Here...",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OID"));
        } else if (name.equals(CONFIG_DATA)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "Comment Here...",
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXT_VALUE"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_DATA)) {
            return new Descriptor(IDescriptor.STRING_LIST, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXT_VALUE"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {
            Extension ext = null;

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            ObjectIdentifier oid = new ObjectIdentifier(getConfig(CONFIG_OID));

            ext = getExtension(oid.toString(), info);

            if (ext == null) {
                populate(null, info);
            }

            if (name.equals(VAL_CRITICAL)) {
                ext = getExtension(oid.toString(), info);
                if (ext == null) {
                    return;
                }
                boolean val = Boolean.valueOf(value).booleanValue();
                ext.setCritical(val);
            } else if (name.equals(VAL_DATA)) {
                ext = getExtension(oid.toString(), info);
                if (ext == null) {
                    return;
                }
                byte data[] = getBytes(value);
                ext.setExtensionValue(data);
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }

            replaceExtension(ext.getExtensionId().toString(), ext, info);
        } catch (EProfileException e) {
            CMS.debug("GenericExtDefault: setValue " + e.toString());
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        Extension ext = null;

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        ObjectIdentifier oid = new ObjectIdentifier(getConfig(CONFIG_OID));

        ext = getExtension(oid.toString(), info);

        if (ext == null) {
            try {
                populate(null, info);

            } catch (EProfileException e) {
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {

            ext = getExtension(oid.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_DATA)) {

            ext = getExtension(oid.toString(), info);

            if (ext == null)
                return "";

            byte data[] = ext.getExtensionValue();

            if (data == null)
                return "";

            return toStr(data);
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_OID),
                getConfig(CONFIG_DATA)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_GENERIC_EXT", params);
    }

    public String toStr(byte data[]) {
        StringBuffer b = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            if ((data[i] & 0xff) < 16) {
                b.append("0");
            }
            b.append(Integer.toString((data[i] & 0xff), 0x10));
        }
        return b.toString();
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        Extension ext = createExtension(request);

        addExtension(ext.getExtensionId().toString(), ext, info);
    }

    public Extension createExtension(IRequest request) {
        Extension ext = null;

        try (DerOutputStream out = new DerOutputStream()) {
            boolean critical = getConfigBoolean(CONFIG_CRITICAL);
            ObjectIdentifier oid = new ObjectIdentifier(getConfig(CONFIG_OID));
            byte data[] = null;

            if (request == null) {
                data = getBytes(getConfig(CONFIG_DATA));
            } else {
                data = getBytes(mapPattern(request, getConfig(CONFIG_DATA)));
            }

            out.putOctetString(data);

            ext = new Extension(oid, critical, out.toByteArray());
        } catch (Exception e) {
            CMS.debug("GenericExtDefault: createExtension " +
                    e.toString());
        }
        return ext;
    }
}
