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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.repository.IRepositoryRecord;

/**
 * A class represents a repository record.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class RepositoryRecord implements IRepositoryRecord {

    /**
     *
     */
    private static final long serialVersionUID = 1648450747848783853L;
    private BigInteger mSerialNo = null;
    private String mPublishingStatus = null;
    private String mDescription = null;

    protected static Vector<String> mNames = new Vector<String>();
    static {
        mNames.addElement(IRepositoryRecord.ATTR_SERIALNO);
        mNames.addElement(IRepositoryRecord.ATTR_PUB_STATUS);
        mNames.addElement(IRepositoryRecord.ATTR_DESCRIPTION);
    }

    /**
     * Constructs a repository record.
     * <P>
     */
    public RepositoryRecord() {
    }

    /**
     * Sets attribute.
     */
    public void set(String name, Object obj) throws EBaseException {
        if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_SERIALNO)) {
            mSerialNo = (BigInteger) obj;
        } else if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_PUB_STATUS)) {
            mPublishingStatus = (String) obj;
        } else if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_DESCRIPTION)) {
            mDescription = (String) obj;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    /**
     * Retrieves attribute from this record.
     */
    public Object get(String name) throws EBaseException {
        if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_SERIALNO)) {
            return mSerialNo;
        } else if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_PUB_STATUS)) {
            return mPublishingStatus;
        } else if (name.equalsIgnoreCase(IRepositoryRecord.ATTR_DESCRIPTION)) {
            return mDescription;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    /**
     * Deletes an attribute.
     */
    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }

    /**
     * Retrieves a list of attribute names.
     */
    public Enumeration<String> getElements() {
        return mNames.elements();
    }

    public Enumeration<String> getSerializableAttrNames() {
        return mNames.elements();
    }

    /**
     * Retrieves serial number.
     */
    public BigInteger getSerialNumber() {
        return mSerialNo;
    }

    public String getPublishingStatus() {
        return mPublishingStatus;
    }

    public String getDescription() {
        return mDescription;
    }
}
