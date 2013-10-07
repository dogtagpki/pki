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

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.Extension;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements an enrollment default policy
 * that populates a user-supplied extension
 * into the certificate template.
 *
 * @version $Revision$, $Date$
 */
public class UserExtensionDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "userExtCritical";
    public static final String CONFIG_OID = "userExtOID";

    public static final String VAL_CRITICAL = "userExtCritical";
    public static final String VAL_OID = "userExtOID";

    public UserExtensionDefault() {
        super();
        addValueName(VAL_OID);
        addConfigName(CONFIG_OID);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        if (name.equals(CONFIG_OID)) {
            return new Descriptor(IDescriptor.STRING, null,
                    "Comment Here...",
                    CMS.getUserMessage(locale, "CMS_PROFILE_OID"));
        } else {
            return null;
        }
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_OID)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OID"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
            X509CertInfo info, String value)
            throws EPropertyException {
        // Nothing to do for read-only values
    }

    public String getValue(String name, Locale locale,
            X509CertInfo info)
            throws EPropertyException {
        if (name == null) {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_OID)) {
            Extension ext = getExtension(getConfig(CONFIG_OID), info);

            if (ext == null) {
                // do something here
                return "";
            }
            return ext.getExtensionId().toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_USER_EXT", getConfig(CONFIG_OID));
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
            throws EProfileException {
        CertificateExtensions inExts = null;
        String oid = getConfig(CONFIG_OID);

        inExts = request.getExtDataInCertExts(IEnrollProfile.REQUEST_EXTENSIONS);
        if (inExts == null)
            return;
        Extension ext = getExtension(getConfig(CONFIG_OID), inExts);
        if (ext == null) {
            CMS.debug("UserExtensionDefault: no user ext supplied for " + oid);
            return;
        }

        // user supplied the ext that's allowed, replace the def set by system
        deleteExtension(oid, info);
        CMS.debug("UserExtensionDefault: using user supplied ext for " + oid);
        addExtension(oid, ext, info);
    }
}
