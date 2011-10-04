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


import java.util.*;
import java.io.*;
import java.math.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.keydb.*;
import com.netscape.cmscore.dbs.*;


/**
 * A class represents a list of key records.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KeyRecordList implements IKeyRecordList {

    private IDBVirtualList mVlist = null;

    /**
     * Constructs a key list.
     */
    public KeyRecordList(IDBVirtualList vlist) {
        mVlist = vlist;
    }

    /**
     * Retrieves the size of key list. 
     */
    public int getSize() {
        return mVlist.getSize();
    }

    public  int getSizeBeforeJumpTo() {

        return mVlist.getSizeBeforeJumpTo();

    }

    public int getSizeAfterJumpTo() {

        return mVlist.getSizeAfterJumpTo();
    }

    public IKeyRecord getKeyRecord(int i) {
        KeyRecord record = (KeyRecord) mVlist.getElementAt(i);

        if (record == null) return null;

        return record; 
    } 
    /**
     * Retrieves requests.
     */
    public Enumeration getKeyRecords(int startidx, int endidx)
        throws EBaseException {
        Vector entries = new Vector();

        for (int i = startidx; i <= endidx; i++) {
            Object element = mVlist.getElementAt(i);

            if (element != null) {
                entries.addElement(element);
            }
        }
        if (entries != null) {
            return entries.elements();
        } else {
            return null;
        }
    }
}
