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
import java.security.cert.CertificateException;
import java.util.Locale;

import netscape.security.x509.CertificateVersion;
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
public class CertificateVersionDefault extends EnrollExtDefault {

    public static final String CONFIG_VERSION = "certVersionNum";

    public static final String VAL_VERSION = "certVersionNum";

    public CertificateVersionDefault() {
        super();
        addValueName(VAL_VERSION);

        addConfigName(CONFIG_VERSION);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_VERSION)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "3",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VERSION"));
        } else {
            return null;
        }
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
        if (name.equals(CONFIG_VERSION)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(
                            "CMS_INVALID_PROPERTY", CONFIG_VERSION));
            }
        }
        super.setConfig(name, value);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_VERSION)) {
            return new Descriptor(IDescriptor.INTEGER, null,
                    "3",
                    CMS.getUserMessage(locale, "CMS_PROFILE_VERSION"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        try {

            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
            if (name.equals(VAL_VERSION)) {
                if (value == null || value.equals(""))
                    throw new EPropertyException(name + " cannot be empty");
                else {
                    int version = Integer.valueOf(value).intValue() - 1;

                    if (version == CertificateVersion.V1)
                        info.set(X509CertInfo.VERSION,
                                new CertificateVersion(CertificateVersion.V1));
                    else if (version == CertificateVersion.V2)
                        info.set(X509CertInfo.VERSION,
                                new CertificateVersion(CertificateVersion.V2));
                    else if (version == CertificateVersion.V3)
                        info.set(X509CertInfo.VERSION,
                                new CertificateVersion(CertificateVersion.V3));
                }
            } else {
                throw new EPropertyException(CMS.getUserMessage(
                            locale, "CMS_INVALID_PROPERTY", name));
            }
        } catch (IOException e) {
            CMS.debug("CertificateVersionDefault: setValue " + e.toString());
        } catch (CertificateException e) {
            CMS.debug("CertificateVersionDefault: setValue " + e.toString());
        }
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }

        if (name.equals(VAL_VERSION)) {
            CertificateVersion v = null;
            try {
                v = (CertificateVersion) info.get(
                        X509CertInfo.VERSION);
            } catch (Exception e) {
            }

            if (v == null)
                throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
            int version = v.compare(0);

            return "" + (version + 1);
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_VERSION)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_CERT_VERSION", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        String v = getConfig(CONFIG_VERSION);
        int version = Integer.valueOf(v).intValue() - 1;

        try {
            if (version == CertificateVersion.V1)
                info.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V1));
            else if (version == CertificateVersion.V2)
                info.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V2));
            else if (version == CertificateVersion.V3)
                info.set(X509CertInfo.VERSION,
                        new CertificateVersion(CertificateVersion.V3));
            else {
                throw new EProfileException(CMS.getUserMessage(
                        getLocale(request), "CMS_INVALID_PROPERTY", CONFIG_VERSION));
            }
        } catch (IOException e) {
        } catch (CertificateException e) {
        }
    }
}
