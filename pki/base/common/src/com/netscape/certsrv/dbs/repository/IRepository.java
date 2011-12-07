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
package com.netscape.certsrv.dbs.repository;

import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;

/**
 * An interface represents a generic repository. It maintains unique serial
 * number within repository.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IRepository {

    /**
     * Retrieves the next serial number, and also increase the serial number by
     * one.
     * 
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public BigInteger getNextSerialNumber() throws EBaseException;

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException;

    /**
     * Retrieves the next serial number without increasing the serial number.
     * 
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public BigInteger getTheSerialNumber() throws EBaseException;

    /**
     * Set the maximum serial number.
     * 
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number
     */
    public void setMaxSerial(String serial) throws EBaseException;

    /**
     * Set the maximum serial number in next range.
     * 
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number in next
     *                range
     */
    public void setNextMaxSerial(String serial) throws EBaseException;

    /**
     * Checks to see if a new range is needed, or if we have reached the end of
     * the current range, or if a range conflict has occurred.
     * 
     * @exception EBaseException failed to check next range for conflicts
     */
    public void checkRanges() throws EBaseException;

    /**
     * Sets whether serial number management is enabled for certs and requests.
     * 
     * @param value true/false
     * @exception EBaseException failed to set
     */
    public void setEnableSerialMgmt(boolean value) throws EBaseException;

}
