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
import java.security.*;
import java.util.*;
import com.netscape.cms.profile.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;
import netscape.security.util.*;


/**
 * This class implements an enrollment default policy
 * that populates Authority Key Identifier extension
 * into the certificate template.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class AuthorityKeyIdentifierExtDefault extends CAEnrollDefault {

    public static final String VAL_CRITICAL = "critical";
    public static final String VAL_KEY_ID = "keyid";

    public AuthorityKeyIdentifierExtDefault() {
        super();

        addValueName(VAL_CRITICAL);
        addValueName(VAL_KEY_ID);
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        super.init(profile, config);
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.STRING, 
                    IDescriptor.READONLY, null, CMS.getUserMessage(locale,
                        "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_KEY_ID)) {
            return new Descriptor(IDescriptor.STRING, 
                    IDescriptor.READONLY, null, CMS.getUserMessage(locale,
                        "CMS_PROFILE_KEY_ID"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
        X509CertInfo info, String value)
        throws EPropertyException {
        if (name == null) { 
            throw new EPropertyException(CMS.getUserMessage( 
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_CRITICAL)) {
            // do nothing for read only value
        } else if (name.equals(VAL_KEY_ID)) {
            // do nothing for read only value
        } else {
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


        AuthorityKeyIdentifierExtension ext =
                (AuthorityKeyIdentifierExtension) getExtension(
                    PKIXExtensions.AuthorityKey_Id.toString(), info);

        if(ext == null)
        {
            try {
                populate(null,info);

            } catch (EProfileException e) {
                CMS.debug("BasicConstraintsExtDefault: getValue " + e.toString());
                 throw new EPropertyException(CMS.getUserMessage(
                      locale, "CMS_INVALID_PROPERTY", name));
            }

        }
        if (name.equals(VAL_CRITICAL)) {
             ext = 
                (AuthorityKeyIdentifierExtension) getExtension(
                    PKIXExtensions.AuthorityKey_Id.toString(), info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_KEY_ID)) {
            ext =
                (AuthorityKeyIdentifierExtension) getExtension(
                    PKIXExtensions.AuthorityKey_Id.toString(), info);

            if (ext == null) {
                // do something here
                return "";
            }
            KeyIdentifier kid = null;

            try {
                kid = (KeyIdentifier)
                        ext.get(AuthorityKeyIdentifierExtension.KEY_ID);
            } catch (IOException e) {
                //
                CMS.debug(e.toString());
            }
            if (kid == null) 
                return "";
            return toHexString(kid.getIdentifier());
        } else {
            throw new EPropertyException(CMS.getUserMessage( 
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_AKI_EXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
        throws EProfileException {
        AuthorityKeyIdentifierExtension ext = createExtension(info);

        addExtension(PKIXExtensions.AuthorityKey_Id.toString(), ext, info);
    }

    public AuthorityKeyIdentifierExtension createExtension(X509CertInfo info) {
        KeyIdentifier kid = null;
        String localKey = getConfig("localKey");
        if (localKey != null && localKey.equals("true")) {
          kid = getKeyIdentifier(info);
        } else {
          kid = getCAKeyIdentifier();
        }

        if (kid == null)
            return null;
        AuthorityKeyIdentifierExtension ext = null;

        try {
            ext = new AuthorityKeyIdentifierExtension(false, kid, null, null);
        } catch (IOException e) {
            CMS.debug("AuthorityKeyIdentifierExtDefault: createExtension " + 
                e.toString());
        }
        return ext;
    }
}
