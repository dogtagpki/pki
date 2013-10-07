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

import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.extensions.ExtendedKeyUsageExtension;
import netscape.security.util.ObjectIdentifier;
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
import com.netscape.cms.profile.def.ExtendedKeyUsageExtDefault;
import com.netscape.cms.profile.def.NoDefault;
import com.netscape.cms.profile.def.UserExtensionDefault;

/**
 * This class implements the extended key usage extension constraint.
 * It checks if the extended key usage extension in the certificate
 * template satisfies the criteria.
 *
 * @version $Revision$, $Date$
 */
public class ExtendedKeyUsageExtConstraint extends EnrollConstraint {

    public static final String CONFIG_CRITICAL = "exKeyUsageCritical";
    public static final String CONFIG_OIDS =
            "exKeyUsageOIDs";

    public ExtendedKeyUsageExtConstraint() {
        super();
        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_OIDS);
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
        } else if (name.equals(CONFIG_OIDS)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OIDS"));
        }
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        ExtendedKeyUsageExtension ext = (ExtendedKeyUsageExtension)
                getExtension(ExtendedKeyUsageExtension.OID, info);

        if (ext == null) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_EXTENSION_NOT_FOUND",
                            ExtendedKeyUsageExtension.OID));
        }

        // check criticality
        String value = getConfig(CONFIG_CRITICAL);

        if (!isOptional(value)) {
            boolean critical = getBoolean(value);

            if (critical != ext.isCritical()) {
                throw new ERejectException(
                        CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_CRITICAL_NOT_MATCHED"));
            }
        }

        // Build local cache of configured OIDs
        Vector<String> mCache = new Vector<String>();
        StringTokenizer st = new StringTokenizer(getConfig(CONFIG_OIDS), ",");

        while (st.hasMoreTokens()) {
            String oid = st.nextToken();

            mCache.addElement(oid);
        }

        // check OIDs
        Enumeration<ObjectIdentifier> e = ext.getOIDs();

        while (e.hasMoreElements()) {
            ObjectIdentifier oid = e.nextElement();

            if (!mCache.contains(oid.toString())) {
                throw new ERejectException(
                        CMS.getUserMessage(
                                getLocale(request),
                                "CMS_PROFILE_OID_NOT_MATCHED",
                                oid.toString()));
            }
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL),
                getConfig(CONFIG_OIDS)
            };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_EXTENDED_KEY_EXT_TEXT",
                params);
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof ExtendedKeyUsageExtDefault)
            return true;
        if (def instanceof UserExtensionDefault)
            return true;
        return false;
    }
}
