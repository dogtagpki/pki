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
package com.netscape.certsrv.dbs.keydb;

import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;

/**
 * A class represents a list of key records.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IKeyRecordList {

    /**
     * Retrieves the size of key list.
     * 
     * @return size of key list
     */
    public int getSize();

    /**
     * Retrieves key records.
     * 
     * @param startidx start index
     * @param endidx end index
     * @return key records
     * @exception EBaseException failed to retrieve key records
     */
    public Enumeration<IKeyRecord> getKeyRecords(int startidx, int endidx)
            throws EBaseException;
}
