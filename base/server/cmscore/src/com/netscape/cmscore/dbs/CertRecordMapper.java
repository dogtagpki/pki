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

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.cmscore.util.Debug;

/**
 * A class represents a mapper to serialize
 * certificate record into database.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertRecordMapper implements IDBAttrMapper {

    private ICertificateRepository mDB = null;

    public CertRecordMapper(ICertificateRepository db) {
        mDB = db;
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        Vector<String> v = new Vector<String>();

        v.addElement(CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);
        return v.elements();
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs)
            throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        CertRecord rec = (CertRecord) obj;
        attrs.add(new LDAPAttribute(
                CertDBSchema.LDAP_ATTR_CERT_RECORD_ID,
                rec.getSerialNumber().toString()));
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
