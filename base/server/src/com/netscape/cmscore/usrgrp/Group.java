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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IAttrSet;
import com.netscape.certsrv.usrgrp.IGroupConstants;
import com.netscape.cmscore.apps.CMS;

/**
 * A class represents a group.
 *
 * @author cfu
 * @version $Revision$, $Date$
 */
public class Group implements IAttrSet, IGroupConstants {
    /**
     *
     */
    private static final long serialVersionUID = -1264387079578766750L;

    private String mName = null;

    // TODO: replace Vector with Set
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
    public Group(String name) {
        mName = name;
    }

    /**
     * Retrieves the group name.
     *
     * @return the group name
     */
    public String getName() {
        return mName;
    }

    /**
     * Retrieves group identifier.
     *
     * @return the group id
     */
    public String getGroupID() {
        return mName;
    }

    /**
     * Retrieves group description.
     *
     * @return description
     */
    public String getDescription() {
        return mDescription;
    }

    /**
     * Adds new member.
     *
     * @param name the given name.
     */
    public void addMemberName(String name) {
        if (isMember(name)) return;
        mMembers.addElement(name);
    }

    /**
     * Retrieves a list of member names.
     *
     * @return a list of member names for this group.
     */
    public Enumeration<String> getMemberNames() {
        return mMembers.elements();
    }

    /**
     * Checks if the given name is member of this group.
     *
     * @param name the given name
     * @return true if the given name is the member of this group; otherwise false.
     */
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
        if (name.equals(ATTR_NAME)) {
            mName = null;
        } else if (name.equals(ATTR_ID)) {
            mName = null;
        } else if (name.equals(ATTR_MEMBERS)) {
            mMembers.clear();
        } else if (name.equals(ATTR_DESCRIPTION)) {
            mDescription = null;
        } else {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", name));
        }
    }

    public Enumeration<String> getElements() {
        return mNames.elements();
    }
}
