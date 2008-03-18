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


import java.io.*;
import java.util.*;
import com.netscape.cms.profile.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;


/**
 * This class implements an enrollment default policy
 * that populates a user-supplied extension
 * into the certificate template.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class UserExtensionDefault extends EnrollExtDefault {

    public static final String CONFIG_OID = "userExtOID";

    public static final String VAL_CRITICAL = "userExtCritical";
    public static final String VAL_OID = "userExtOID";
    public static final String VAL_VALUE = "userExtValue";

    public UserExtensionDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_OID);
        addValueName(VAL_VALUE);
        addConfigName(CONFIG_OID);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY, 
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_OID)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OID"));
        } else if (name.equals(VAL_VALUE)) {
            return new Descriptor(IDescriptor.STRING,
                    IDescriptor.READONLY,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_EXT_VALUE"));
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
        if (name.equals(VAL_CRITICAL)) {
            Extension ext = getExtension(getConfig(CONFIG_OID), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_OID)) {
            Extension ext = getExtension(getConfig(CONFIG_OID), info);

            if (ext == null) {
                // do something here
                return "";
            }
            return ext.getExtensionId().toString();
        } else if (name.equals(VAL_VALUE)) {
            Extension ext = getExtension(getConfig(CONFIG_OID), info);

            if (ext == null) {
                // do something here
                return "";
            }
            return toHexString(ext.getExtensionValue());
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

        inExts = request.getExtDataInCertExts(IEnrollProfile.REQUEST_EXTENSIONS);
        Extension ext = getExtension(getConfig(CONFIG_OID), inExts);
        if (ext == null)
          return;
        addExtension(getConfig(CONFIG_OID), ext, info);
    }
}
