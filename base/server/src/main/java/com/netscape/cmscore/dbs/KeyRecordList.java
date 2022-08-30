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

import java.util.Enumeration;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBVirtualList;

/**
 * A class represents a list of key records.
 *
 * @author thomask
 */
public class KeyRecordList {

    private DBVirtualList<KeyRecord> mVlist = null;

    /**
     * Constructs a key list.
     */
    public KeyRecordList(DBVirtualList<KeyRecord> vlist) {
        mVlist = vlist;
    }

    /**
     * Retrieves the size of key list.
     *
     * @return size of key list
     */
    public int getSize() {
        return mVlist.getSize();
    }

    public int getSizeBeforeJumpTo() {

        return mVlist.getSizeBeforeJumpTo();

    }

    public int getSizeAfterJumpTo() {

        return mVlist.getSizeAfterJumpTo();
    }

    public KeyRecord getKeyRecord(int i) {
        KeyRecord record = mVlist.getElementAt(i);

        if (record == null)
            return null;

        return record;
    }

    /**
     * Retrieves key records.
     *
     * @param startidx start index
     * @param endidx end index
     * @return key records
     * @exception EBaseException failed to retrieve key records
     */
    public Enumeration<KeyRecord> getKeyRecords(int startidx, int endidx)
            throws EBaseException {
        Vector<KeyRecord> entries = new Vector<>();

        for (int i = startidx; i <= endidx; i++) {
            KeyRecord element = mVlist.getElementAt(i);

            if (element != null) {
                entries.addElement(element);
            }
        }
        return entries.elements();
    }
}
