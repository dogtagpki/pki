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
package com.netscape.cmscore.dbs;


import java.math.*;
import java.io.*;
import java.util.*;
import netscape.ldap.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.cmscore.dbs.*;
import com.netscape.cmscore.util.Debug;


/**
 * A class represents a mapper to serialize 
 * revocation information into database.
 * <P>
 *
 * @author  thomask
 * @version $Revision$, $Date$
 */
public class RevocationInfoMapper implements IDBAttrMapper {

    protected static Vector mNames = new Vector();
    static {
        mNames.addElement(CertDBSchema.LDAP_ATTR_REVO_INFO);
    }

    /**
     * Constructs revocation information mapper.
     */
    public RevocationInfoMapper() {
    }

    public Enumeration getSupportedLDAPAttributeNames() {
        return mNames.elements();
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name, 
        Object obj, LDAPAttributeSet attrs) 
        throws EBaseException {
        try {
            // in format of <date>;<extensions>
            String value = "";
            RevocationInfo info = (RevocationInfo) obj;
            Date d = info.getRevocationDate();

            value = DateMapper.dateToDB(d);
            CRLExtensions exts = info.getCRLEntryExtensions();
            // CRLExtension's DER encoding and decoding does not work!
            // That is why we need to do our own serialization.
            Enumeration e = exts.getElements();

            while (e.hasMoreElements()) {
                Extension ext = (Extension) e.nextElement();

                if (ext instanceof CRLReasonExtension) {
                    RevocationReason reason = 
                        ((CRLReasonExtension) ext).getReason();

                    value = value + ";CRLReasonExtension=" + 	
                            Integer.toString(reason.toInt());
                } else if (ext instanceof InvalidityDateExtension) {
                    Date invalidityDate = 
                        ((InvalidityDateExtension) ext).getInvalidityDate();

                    value = value + ";InvalidityDateExtension=" + 	
                            DateMapper.dateToDB(invalidityDate);
                } else {
                    Debug.trace("XXX skipped extension");
                }
            }
            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_REVO_INFO, 
                    value));
        } catch (Exception e) {
            Debug.trace(e.toString());
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs, 
        String name, IDBObj parent) throws EBaseException {
        try {
            LDAPAttribute attr = attrs.getAttribute(
                    CertDBSchema.LDAP_ATTR_REVO_INFO);

            if (attr == null)
                return;
            String value = (String) attr.getStringValues().nextElement();
            int i = value.indexOf(';'); // look for 1st ";"
            String str = null;
            CRLExtensions exts = new CRLExtensions();
            Date d = null;

            if (i == -1) {
                // only date found; no extensions
                d = DateMapper.dateFromDB(value);
            } else {
                String s = value;

                str = s.substring(0, i);
                d = DateMapper.dateFromDB(str);
                s = s.substring(i + 1);
                do {
                    i = s.indexOf(';');
                    if (i == -1) {
                        str = s;
                    } else {
                        str = s.substring(0, i);
                        s = s.substring(i + 1);
                    }
                    if (str.startsWith("CRLReasonExtension=")) {
                        String reasonStr = str.substring(19);
                        RevocationReason reason = RevocationReason.fromInt(
                                Integer.parseInt(reasonStr));
                        CRLReasonExtension ext = new CRLReasonExtension(reason);

                        exts.set(CRLReasonExtension.NAME, ext);
                    } else if (str.startsWith("InvalidityDateExtension=")) {
                        String invalidityDateStr = str.substring(24);
                        Date invalidityDate = DateMapper.dateFromDB(invalidityDateStr);
                        InvalidityDateExtension ext =
                            new InvalidityDateExtension(invalidityDate);

                        exts.set(InvalidityDateExtension.NAME, ext);
                    } else {
                        Debug.trace("XXX skipped extension");
                    }
                }
                while (i != -1);
            }	
            RevocationInfo info = new RevocationInfo(d, exts);

            parent.set(name, info);
        } catch (Exception e) {
            Debug.trace(e.toString());
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name));
        }
    }

    public String mapSearchFilter(String name, String op, String value)
        throws EBaseException {
        return CertDBSchema.LDAP_ATTR_REVO_INFO + op + value;
    }
}
