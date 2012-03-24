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
package com.netscape.certsrv.publish;

/**
 * 
 * Class representing a LdapMapper.
 * 
 * @version $Revision$ $Date$
 */

public class MapperProxy {
    private boolean mEnable;
    private ILdapMapper mMapper;

    /**
     * 
     * Contructs MapperProxy .
     * 
     * @param enable Enabled or not.
     * @param mapper Corresponding ILdapMapper object.
     */
    public MapperProxy(boolean enable, ILdapMapper mapper) {
        mEnable = enable;
        mMapper = mapper;
    }

    /**
     * 
     * Returns if enabled.
     * 
     * @return true if enabled, otherwise false.
     */
    public boolean isEnable() {
        return mEnable;
    }

    /**
     * 
     * Returns ILdapMapper object.
     * 
     * @return Intance of ILdapMapper object.
     */
    public ILdapMapper getMapper() {
        return mMapper;
    }
}
