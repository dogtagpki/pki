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
import java.security.cert.*;
import netscape.ldap.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.cmscore.dbs.*;
import com.netscape.cmscore.util.Debug;
import com.netscape.certsrv.apps.CMS;


/**
 * A class represents a mapper to serialize 
 * certificate record into database.
 * <P>
 *
 * @author  thomask
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class CertRecordMapper implements IDBAttrMapper {

    private ICertificateRepository mDB = null;

    public CertRecordMapper(ICertificateRepository db) {
        mDB = db;
    }

    public Enumeration getSupportedLDAPAttributeNames() {
        Vector v = new Vector();

        v.addElement(CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);
        return v.elements();
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name, 
        Object obj, LDAPAttributeSet attrs) 
        throws EBaseException {
        try {
            CertRecord rec = (CertRecord) obj;

            attrs.add(new LDAPAttribute(
                    CertDBSchema.LDAP_ATTR_CERT_RECORD_ID,
                    rec.getSerialNumber().toString()));
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
                    CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);

            if (attr == null)
                return;
            String serialno = (String) attr.getStringValues().nextElement();
            ICertRecord rec = mDB.readCertificateRecord(
                    new BigInteger(serialno));

            parent.set(name, rec);
        } catch (Exception e) {
            Debug.trace(e.toString());
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name));
        }
    }

    public String mapSearchFilter(String name, String op, String value)
        throws EBaseException {
        return name + op + value;
    }
}
