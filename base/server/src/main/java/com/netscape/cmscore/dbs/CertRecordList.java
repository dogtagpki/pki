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
 * A class represents a list of certificate records.
 *
 * @author thomask mzhao
 * @version $Revision$, $Date$
 */
public class CertRecordList {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CertRecordList.class);
    private DBVirtualList<CertRecord> mVlist = null;

    /**
     * Constructs a request list.
     */
    public CertRecordList(DBVirtualList<CertRecord> vlist) {
        mVlist = vlist;
    }

    /**
     * Gets the current index.
     *
     * @return current index
     */
    public int getCurrentIndex() {
        return mVlist.getCurrentIndex();
    }

    /**
     * Retrieves the size of request list.
     *
     * @return size
     */
    public int getSize() {
        // get the size of the virtual list
        return mVlist.getSize();
    }

    /**
     * Gets size before jump to index.
     *
     * @return size
     */
    public int getSizeBeforeJumpTo() {
        return mVlist.getSizeBeforeJumpTo();

    }

    /**
     * Gets size after jump to index.
     *
     * @return size
     */
    public int getSizeAfterJumpTo() {
        return mVlist.getSizeAfterJumpTo();

    }

    /**
     * Process certificate record as soon as it is returned.
     *
     * kmccarth: changed to ignore startidx and endidx because VLVs don't
     * provide a stable list.
     *
     * @param startidx starting index
     * @param endidx ending index
     * @param ep element processor
     * @exception EBaseException failed to process cert records
     */
    public void processCertRecords(int startidx, int endidx,
            ElementProcessor<CertRecord> ep) throws EBaseException {
        int i = 0;
        while (i < mVlist.getSize()) {
            CertRecord element = mVlist.getElementAt(i);
            if (element != null) {
                ep.process(element);
            }
            i++;
        }
    }

    /**
     * Retrieves requests.
     * It's no good to call this if you didnt check
     * if the startidx, endidx are valid.
     *
     * @param startidx starting index
     * @param endidx ending index
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<CertRecord> getCertRecords(int startidx, int endidx)
            throws EBaseException {
        Vector<CertRecord> entries = new Vector<>();

        for (int i = startidx; i <= endidx; i++) {
            CertRecord element = mVlist.getElementAt(i);

            //  logger.debug("gerCertRecords[" + i + "] element: " + element);
            if (element != null) {
                entries.addElement(element);
            }
        }
        return entries.elements();
    }

    /**
     * Gets one single record at a time similar to
     * processCertRecords but no extra class needed.
     *
     * @param index position of the record to be retrieved
     * @return object
     * @exception EBaseException failed to retrieve
     */
    public CertRecord getCertRecord(int index)
            throws EBaseException {

        return mVlist.getElementAt(index);

    }

}
