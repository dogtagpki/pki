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
package com.netscape.cmscore.usrgrp;


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.apps.*;


/**
 * A class represents a group.
 *
 * @author cfu
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class Group implements IGroup {
    private IUsrGrp mBase = null;
    private String mName = null;
    private Vector mMembers = new Vector();
    private String mDescription = null;

    private static final Vector mNames = new Vector();
    static {
        mNames.addElement(ATTR_NAME);
        mNames.addElement(ATTR_ID);
        mNames.addElement(ATTR_DESCRIPTION);
        mNames.addElement(ATTR_MEMBERS);
    }

    /**
     * Constructs local group.
     */
    public Group(IUsrGrp base, String name) {
        mBase = base;
        mName = name;
    }

    public String getName() {
        return mName;
    }

    public String getGroupID() {
        return mName;
    }

    public String getDescription() {
        return mDescription;
    }

    public void addMemberName(String name) {
        mMembers.addElement(name);
    }

    public Enumeration getMemberNames() {
        return mMembers.elements();
    }

    public boolean isMember(String name) {
        for (int i = 0; i < mMembers.size(); i++) {
            String id = (String) mMembers.elementAt(i);

            if (name.equals(id)) {
                return true;
            }
        }
        return false;
    }

    public void set(String name, Object object) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_ID)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_MEMBERS)) {
            mMembers = (Vector) object;
        } else if (name.equals(ATTR_DESCRIPTION)) {
            mDescription = (String) object;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    public Object get(String name) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            return getName();
        } else if (name.equals(ATTR_ID)) {
            return getGroupID();
        } else if (name.equals(ATTR_MEMBERS)) {
            return mMembers;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    public void delete(String name) throws EBaseException {
        throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
    }

    public Enumeration getElements() {
        return mNames.elements();
    }
}
