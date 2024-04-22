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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.DBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A class represents a mapper to serialize
 * certificate record into database.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertRecordMapper extends DBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecordMapper.class);

    private CertificateRepository mDB;

    public CertRecordMapper(CertificateRepository db) {
        mDB = db;
    }

    @Override
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        Vector<String> v = new Vector<>();

        v.addElement(CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);
        return v.elements();
    }

    @Override
    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs)
            throws EBaseException {

        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }

        CertRecord rec = (CertRecord) obj;

        logger.debug("CertRecordMapper: Mapping " + name + " to " + CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);
        attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_CERT_RECORD_ID, rec.getSerialNumber().toString()));
    }

    @Override
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        try {
            LDAPAttribute attr = attrs.getAttribute(
                    CertDBSchema.LDAP_ATTR_CERT_RECORD_ID);

            if (attr == null)
                return;
            String serialno = attr.getStringValues().nextElement();
            CertRecord rec = mDB.readCertificateRecord(new BigInteger(serialno));

            parent.set(name, rec);
        } catch (Exception e) {
            logger.error("CertRecordMapper: " + e.getMessage(), e);
            throw new DBException(CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name), e);
        }
    }

    @Override
    public String mapSearchFilter(String name, String op, String value)
            throws EBaseException {
        return name + op + value;
    }
}
