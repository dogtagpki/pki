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


import java.util.*;
import java.io.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;
import com.netscape.cms.profile.common.*;
import com.netscape.cms.profile.def.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.extensions.*;


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
        Vector mCache = new Vector();
        StringTokenizer st = new StringTokenizer(getConfig(CONFIG_OIDS), ",");

        while (st.hasMoreTokens()) {
            String oid = st.nextToken();

            mCache.addElement(oid);
        }

        // check OIDs
        Enumeration e = ext.getOIDs();

        while (e.hasMoreElements()) { 
            ObjectIdentifier oid = (ObjectIdentifier) e.nextElement();

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
