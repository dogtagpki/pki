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
package com.netscape.cmscore.request;

import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.ldap.IRequestMod;

/**
 * The RequestAttr class defines the methods used
 * to transfer data between the various representations of
 * a request. The three forms are:
 * 1) LDAPAttributes (and Modifications)
 * 2) Database record IDBAttrSet
 * 3) IRequest (Request) object
 */
abstract class RequestAttr {

    /**
     *
     */

    abstract void set(ARequestRecord r, Object o);

    abstract Object get(ARequestRecord r);

    abstract void read(IRequestMod a, IRequest r, ARequestRecord rr);

    abstract void add(IRequest r, ARequestRecord rr);

    abstract void mod(ModificationSet mods, IRequest r);

    RequestAttr(String attrName, IDBAttrMapper mapper) {
        mAttrName = attrName;
        mMapper = mapper;
    }

    protected void addmod(ModificationSet mods, Object o) {
        mods.add(mAttrName, Modification.MOD_REPLACE, o);
    }

    String mAttrName;
    IDBAttrMapper mMapper;
}
