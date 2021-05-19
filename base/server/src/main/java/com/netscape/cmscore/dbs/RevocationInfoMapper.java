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

import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.InvalidityDateExtension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBAttrMapper;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * A class represents a mapper to serialize
 * revocation information into database.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class RevocationInfoMapper extends DBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RevocationInfoMapper.class);

    protected static Vector<String> mNames = new Vector<String>();
    static {
        mNames.addElement(CertDBSchema.LDAP_ATTR_REVO_INFO);
    }

    /**
     * Constructs revocation information mapper.
     */
    public RevocationInfoMapper() {
    }

    @Override
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mNames.elements();
    }

    @Override
    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
            Object obj, LDAPAttributeSet attrs)
            throws EBaseException {

        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }

        try {
            // in format of <date>;<extensions>
            StringBuffer value = new StringBuffer();

            RevocationInfo info = (RevocationInfo) obj;
            Date d = info.getRevocationDate();

            value.append(DateMapper.dateToDB(d));
            CRLExtensions exts = info.getCRLEntryExtensions();
            // CRLExtension's DER encoding and decoding does not work!
            // That is why we need to do our own serialization.
            Enumeration<Extension> e = exts.getElements();

            while (e.hasMoreElements()) {
                Extension ext = e.nextElement();

                if (ext instanceof CRLReasonExtension) {
                    RevocationReason reason =
                            ((CRLReasonExtension) ext).getReason();

                    value.append(";CRLReasonExtension=" +
                            Integer.toString(reason.toInt()));
                } else if (ext instanceof InvalidityDateExtension) {
                    Date invalidityDate =
                            ((InvalidityDateExtension) ext).getInvalidityDate();

                    value.append(";InvalidityDateExtension=" +
                            DateMapper.dateToDB(invalidityDate));
                } else {
                    logger.trace("XXX skipped extension");
                }
            }

            logger.debug("RevocationInfoMapper: Mapping " + name + " to " + CertDBSchema.LDAP_ATTR_REVO_INFO);
            attrs.add(new LDAPAttribute(CertDBSchema.LDAP_ATTR_REVO_INFO, value.toString()));

        } catch (Exception e) {
            logger.error("RevocationInfoMapper: " + e.getMessage(), e);
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
    }

    @Override
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent) throws EBaseException {
        try {
            LDAPAttribute attr = attrs.getAttribute(
                    CertDBSchema.LDAP_ATTR_REVO_INFO);

            if (attr == null)
                return;
            String value = attr.getStringValues().nextElement();
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
                        logger.trace("XXX skipped extension");
                    }
                } while (i != -1);
            }
            RevocationInfo info = new RevocationInfo(d, exts);

            parent.set(name, info);
        } catch (Exception e) {
            logger.error("RevocationInfoMapper: " + e.getMessage(), e);
            throw new EDBException(
                    CMS.getUserMessage("CMS_DBS_DESERIALIZE_FAILED", name));
        }
    }

    @Override
    public String mapSearchFilter(String name, String op, String value)
            throws EBaseException {
        return CertDBSchema.LDAP_ATTR_REVO_INFO + op + value;
    }
}
