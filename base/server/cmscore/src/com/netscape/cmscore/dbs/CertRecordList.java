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
import com.netscape.certsrv.dbs.IDBVirtualList;
import com.netscape.certsrv.dbs.IElementProcessor;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;

/**
 * A class represents a list of certificate records.
 * <P>
 *
 * @author thomask mzhao
 * @version $Revision$, $Date$
 */
public class CertRecordList implements ICertRecordList {

    private IDBVirtualList<ICertRecord> mVlist = null;

    /**
     * Constructs a request list.
     */
    public CertRecordList(IDBVirtualList<ICertRecord> vlist) {
        mVlist = vlist;
    }

    public int getCurrentIndex() {
        return mVlist.getCurrentIndex();
    }

    /**
     * Retrieves the size of request list.
     */
    public int getSize() {
        // get the size of the virtual list
        return mVlist.getSize();
    }

    public int getSizeBeforeJumpTo() {
        return mVlist.getSizeBeforeJumpTo();

    }

    public int getSizeAfterJumpTo() {
        return mVlist.getSizeAfterJumpTo();

    }

    /**
     * Process certificate record as soon as it is returned.
     * kmccarth: changed to ignore startidx and endidx because VLVs don't
     * provide a stable list.
     */
    public void processCertRecords(int startidx, int endidx,
            IElementProcessor ep) throws EBaseException {
        int i = 0;
        while (i < mVlist.getSize()) {
            Object element = mVlist.getElementAt(i);
            if (element != null && (!(element instanceof String))) {
                ep.process(element);
            }
            i++;
        }
    }

    /**
     * Retrieves requests.
     * It's no good to call this if you didnt check
     * if the startidx, endidx are valid.
     */
    public Enumeration<ICertRecord> getCertRecords(int startidx, int endidx)
            throws EBaseException {
        Vector<ICertRecord> entries = new Vector<ICertRecord>();

        for (int i = startidx; i <= endidx; i++) {
            ICertRecord element = mVlist.getElementAt(i);

            //  CMS.debug("gerCertRecords[" + i + "] element: " + element);
            if (element != null) {
                entries.addElement(element);
            }
        }
        return entries.elements();
    }

    public ICertRecord getCertRecord(int index)
            throws EBaseException {

        return mVlist.getElementAt(index);

    }

}
