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

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUsrGrp;

/**
 * A class represents a group.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class Group implements IGroup {
    /**
     *
     */
    private static final long serialVersionUID = -1264387079578766750L;
    @SuppressWarnings("unused")
    private IUsrGrp mBase;
    private String mName = null;
    private Vector<String> mMembers = new Vector<String>();
    private String mDescription = null;

    private static final Vector<String> mNames = new Vector<String>();
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

    public Enumeration<String> getMemberNames() {
        return mMembers.elements();
    }

    public boolean isMember(String name) {
        for (int i = 0; i < mMembers.size(); i++) {
            String id = mMembers.elementAt(i);

            if (name.equals(id)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public void set(String name, Object object) throws EBaseException {
        if (name.equals(ATTR_NAME)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_ID)) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        } else if (name.equals(ATTR_MEMBERS)) {
            mMembers = (Vector<String>) object;
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

    public Enumeration<String> getElements() {
        return mNames.elements();
    }
}
