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
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.extensions.*;
import com.netscape.cms.profile.common.*;


/**
 * This class implements an enrollment default policy
 * that populates Extended Key Usage extension
 * into the certificate template.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ExtendedKeyUsageExtDefault extends EnrollExtDefault {

    public static final String CONFIG_CRITICAL = "exKeyUsageCritical";
    public static final String CONFIG_OIDS = "exKeyUsageOIDs";

    public static final String VAL_CRITICAL = "exKeyUsageCritical";
    public static final String VAL_OIDS = "exKeyUsageOIDs";

    public ExtendedKeyUsageExtDefault() {
        super();
        addValueName(VAL_CRITICAL);
        addValueName(VAL_OIDS);
        addConfigName(CONFIG_CRITICAL);
        addConfigName(CONFIG_OIDS);
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
        } else if (name.equals(CONFIG_OIDS)) {
            return new Descriptor(IDescriptor.STRING, null, 
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OIDS"));
        }
        return null;
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(VAL_CRITICAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null,
                    "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CRITICAL"));
        } else if (name.equals(VAL_OIDS)) {
            return new Descriptor(IDescriptor.STRING_LIST, null, null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_OIDS"));
        } else {
            return null;
        }
    }

    public void setValue(String name, Locale locale,
        X509CertInfo info, String value)
        throws EPropertyException {
        ExtendedKeyUsageExtension ext = null;


        ext = (ExtendedKeyUsageExtension)
                    getExtension(ExtendedKeyUsageExtension.OID, info);

        if(ext == null)
        {
            try {
                populate(null,info);

            } catch (EProfileException e) {
                 throw new EPropertyException(CMS.getUserMessage(
                      locale, "CMS_INVALID_PROPERTY", name));
            }

        } 
        if (name == null) { 
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        if (name.equals(VAL_CRITICAL)) {
            ext = (ExtendedKeyUsageExtension)
                    getExtension(ExtendedKeyUsageExtension.OID, info); 
            boolean val = Boolean.valueOf(value).booleanValue(); 

            if(ext == null) {
                return;
            }
            ext.setCritical(val);	    
        } else if (name.equals(VAL_OIDS)) {
            ext = (ExtendedKeyUsageExtension)
                    getExtension(ExtendedKeyUsageExtension.OID, info);
            //		ext.deleteAllOIDs();
            StringTokenizer st = new StringTokenizer(value, ",");

            if(ext == null) {
                return;
            }
            while (st.hasMoreTokens()) {
                String oid = st.nextToken();

                ext.addOID(new ObjectIdentifier(oid));	
            }
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
        try {
            replaceExtension(ExtendedKeyUsageExtension.OID, ext, info);
        } catch (EProfileException e) {
            CMS.debug("ExtendedKeyUsageExtDefault: setValue " + e.toString());
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

        ExtendedKeyUsageExtension ext = (ExtendedKeyUsageExtension)
                getExtension(ExtendedKeyUsageExtension.OID, info);
       

        if(ext == null)
        {
            try {
                populate(null,info);

            } catch (EProfileException e) {
                 throw new EPropertyException(CMS.getUserMessage(
                      locale, "CMS_INVALID_PROPERTY", name));
            }

        }

        if (name.equals(VAL_CRITICAL)) {
            ext = (ExtendedKeyUsageExtension)
                getExtension(ExtendedKeyUsageExtension.OID, info);

            if (ext == null) {
                return null;
            }
            if (ext.isCritical()) {
                return "true";
            } else {
                return "false";
            }
        } else if (name.equals(VAL_OIDS)) {
            ext = (ExtendedKeyUsageExtension)
                getExtension(ExtendedKeyUsageExtension.OID, info);
            StringBuffer sb = new StringBuffer();
            if(ext == null) {
                return "";
            }
            Enumeration e = ext.getOIDs();

            while (e.hasMoreElements()) {
                ObjectIdentifier oid = (ObjectIdentifier)
                    e.nextElement();

                if (!sb.toString().equals("")) {
                    sb.append(",");
                }	
                sb.append(oid.toString());
            }
            return sb.toString();
        } else {
            throw new EPropertyException(CMS.getUserMessage(
                        locale, "CMS_INVALID_PROPERTY", name));
        }
    }

    public String getText(Locale locale) {
        String params[] = {
                getConfig(CONFIG_CRITICAL), 
                getConfig(CONFIG_OIDS)
            };

        return CMS.getUserMessage(locale, 
                "CMS_PROFILE_DEF_EXTENDED_KEY_EXT", params);
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IRequest request, X509CertInfo info)
        throws EProfileException {
        ExtendedKeyUsageExtension ext = createExtension();

        addExtension(ExtendedKeyUsageExtension.OID, ext, info);
    }

    public ExtendedKeyUsageExtension createExtension() {
        ExtendedKeyUsageExtension ext = null; 

        try {
            ext = new ExtendedKeyUsageExtension();
        } catch (Exception e) {
            CMS.debug("ExtendedKeyUsageExtDefault: createExtension " +
                e.toString());
        }
        if (ext == null)
            return null;
        boolean critical = getBoolean(getConfig(CONFIG_CRITICAL));

        ext.setCritical(critical);
        StringTokenizer st = new StringTokenizer(getConfig(CONFIG_OIDS), ",");

        while (st.hasMoreTokens()) {
            String oid = st.nextToken();

            ext.addOID(new ObjectIdentifier(oid));	
        }
        return ext;
    }
}
