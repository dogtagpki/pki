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
 * An interface represents a generic repository. It maintains unique
 * serial number within repository.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IRepository {
    /**
     * Base type for the serial generator
     */
    public enum IDGenerator {
        LEGACY("legacy"),
        LEGACY_2("legacy2");
        private String name;
        private IDGenerator(String name) {
            this.name = name;
        }
        @Override
        public String toString() {
            return name;
        }
        public static IDGenerator fromString(String name) {
            for (IDGenerator idGenerator : values()) {
                if (idGenerator.name.equals(name)) return idGenerator;
            }
            throw new IllegalArgumentException("Invalid ID generator: " + name);
        }
    }
    /**
     * Retrieves the next serial number, and also increase the
     * serial number by one.
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public BigInteger getNextSerialNumber() throws EBaseException;

    /**
     * Retrieves the next serial number without increasing the serial number.
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public BigInteger peekNextSerialNumber() throws EBaseException;

    /**
     * Set the maximum serial number.
     *
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number
     */
    public void setMaxSerial(BigInteger serial) throws EBaseException;

    /**
     * Set the maximum serial number in next range.
     *
     * @param serial maximum number
     * @exception EBaseException failed to set maximum serial number in next range
     */
    public void setNextMaxSerial(BigInteger serial) throws EBaseException;

    /**
     * Checks to see if a new range is needed, or if we have reached the end of the
     * current range, or if a range conflict has occurred.
     *
     * @exception EBaseException failed to check next range for conflicts
     */
    public void checkRanges() throws EBaseException;

    /**
     * Sets whether serial number management is enabled for certs
     * and requests.
     *
     * @param value true/false
     * @exception EBaseException failed to set
     */
    public void setEnableSerialMgmt(boolean value) throws EBaseException;


    /**
     * Gets the id generator associated with the repository instance
     */
    public IDGenerator getIDGenerator();

    /**
     * Sets the id generator associated with the repository instance
     *
     * @param the generator
     */
    public void setIDGenerator(IDGenerator idGenerator);

    /**
     * Sets the id generator associated with the repository instance
     *
     * @param the generator name
     */
    public void setIDGenerator(String idGenerator);

    /**
     * Gets the entry containing the nextRange attribute
     *
     * @return entry DN
     */
    public String getNextRangeDN();
}