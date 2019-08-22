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

import java.util.Hashtable;

import com.netscape.certsrv.base.AttributeNameHelper;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IFilterConverter;

/**
 * A class represents a filter converter
 * that understands how to convert a attribute
 * type from one defintion to another.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class LdapFilterConverter implements IFilterConverter {

    private Hashtable<String, IDBAttrMapper> mReg = null;

    /**
     * Constructs filter convertor.
     */
    public LdapFilterConverter(Hashtable<String, IDBAttrMapper> reg) {
        mReg = reg;
    }

    /**
     * Converts database filter to ldap filter.
     */
    public String convert(String name, String op, String value) {
        AttributeNameHelper h = new AttributeNameHelper(name);
        IDBAttrMapper mapper = mReg.get(
                h.getPrefix().toLowerCase());

        if (mapper == null)
            return null;
        try {
            return mapper.mapSearchFilter(name, op, value);
        } catch (EBaseException e) {
        }
        return null;
    }
}
