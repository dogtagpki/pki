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

import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements an enrollment default policy
 * that populates a Netscape comment extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class CertificateVersionDefault extends EnrollExtDefault {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertificateVersionDefault.class);
    public static final String CONFIG_VERSION = "certVersionNum";
    public static final String VAL_VERSION = "certVersionNum";
    private static final String CMS_INVALID_PROPERTY = "CMS_INVALID_PROPERTY";

    public CertificateVersionDefault() {
        super();
        addValueName(VAL_VERSION);
        addConfigName(CONFIG_VERSION);
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_VERSION)) {
            return new Descriptor(IDescriptor.INTEGER, null, "3", CMS.getUserMessage(locale, "CMS_PROFILE_VERSION"));
        }
        return null;
    }

    @Override
    public void setConfig(String name, String value) throws EPropertyException {
        if (name.equals(CONFIG_VERSION)) {
            try {
                Integer.parseInt(value);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(CMS_INVALID_PROPERTY, CONFIG_VERSION));
            }
        }
        super.setConfig(name, value);
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_VERSION)) {
            return new Descriptor(IDescriptor.INTEGER, null, "3", CMS.getUserMessage(locale, "CMS_PROFILE_VERSION"));
        }
        return null;
    }

    @Override
    public void setValue(String name, Locale locale, X509CertInfo info, String value) throws EPropertyException {
        try {
            if (name == null) {
                throw new EPropertyException(CMS.getUserMessage(locale, CMS_INVALID_PROPERTY, name));
            }
            if (name.equals(VAL_VERSION)) {
                if (value == null || value.equals("")) {
                    throw new EPropertyException(name + " cannot be empty");
                }
                int version = Integer.parseInt(value) - 1;

                if (version == CertificateVersion.V1) {
                    info.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V1));
                } else if (version == CertificateVersion.V2) {
                    info.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V2));
                } else if (version == CertificateVersion.V3) {
                    info.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                }
            } else {
                throw new EPropertyException(CMS.getUserMessage(locale, CMS_INVALID_PROPERTY, name));
            }
        } catch (IOException | CertificateException e) {
            logger.warn("CertificateVersionDefault: setValue " + e.getMessage(), e);
        }
    }

    @Override
    public String getValue(String name, Locale locale, X509CertInfo info) throws EPropertyException {

        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(locale, CMS_INVALID_PROPERTY, name));
        }

        if (name.equals(VAL_VERSION)) {
            CertificateVersion v = null;
            try {
                v = (CertificateVersion) info.get(
                        X509CertInfo.VERSION);
            } catch (Exception e) {
                throw new EPropertyException(CMS.getUserMessage(locale, CMS_INVALID_PROPERTY, name));
            }
            int version = v.compare(0);
            return "" + (version + 1);
        }
        throw new EPropertyException(CMS.getUserMessage(locale, CMS_INVALID_PROPERTY, name));
    }

    @Override
    public String getText(Locale locale) {
        String[] params = {
                getConfig(CONFIG_VERSION)
            };

        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_CERT_VERSION", params);
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Request request, X509CertInfo info) throws EProfileException {
        String v = getConfig(CONFIG_VERSION);
        int version = Integer.parseInt(v) - 1;

        try {
            if (version == CertificateVersion.V1) {
                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V1));
            } else if (version == CertificateVersion.V2) {
                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V2));
            } else if (version == CertificateVersion.V3) {
                info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            } else {
                throw new EProfileException(
                        CMS.getUserMessage(getLocale(request), CMS_INVALID_PROPERTY, CONFIG_VERSION));
            }
        } catch (IOException | CertificateException e) {
            // TODO - Why do we swallow these exceptions?
        }
    }
}
