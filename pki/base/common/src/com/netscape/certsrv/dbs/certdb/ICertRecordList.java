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
package com.netscape.certsrv.dbs.certdb;


import java.util.Enumeration;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IElementProcessor;


/**
 * A class represents a list of certificate records.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ICertRecordList {

    /**
     * Gets the current index.
     *
     * @return current index
     */
    public int getCurrentIndex();

    /**
     * Retrieves the size of request list.
     *
     * @return size
     */
    public int getSize();

    /**
     * Gets size before jump to index.
     *
     * @return size
     */
    public int getSizeBeforeJumpTo();

    /**
     * Gets size after jump to index.
     *
     * @return size
     */
    public int getSizeAfterJumpTo();

    /**
     * Process certificate record as soon as it is returned.
     *
     * @param startidx starting index
     * @param endidx ending index
     * @param ep element processor
     * @exception EBaseException failed to process cert records
     */
    public void processCertRecords(int startidx, int endidx,
        IElementProcessor ep) throws EBaseException;

    /**
     * Retrieves requests.
     * It's no good to call this if you didnt check
     * if the startidx, endidx are valid.
     *
     * @param startidx starting index
     * @param endidx ending index
     * @exception EBaseException failed to retrieve
     */
    public Enumeration getCertRecords(int startidx, int endidx)
        throws EBaseException;

    /**
     * Gets one single record at a time similar to 
     * processCertRecords but no extra class needed.
     * 
     * @param index position of the record to be retrieved
     * @return object
     * @exception EBaseException failed to retrieve
     */
    public ICertRecord getCertRecord(int index)
        throws EBaseException;
}
