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
package com.netscape.certsrv.dbs;

import java.math.BigInteger;

import netscape.ldap.LDAPConnection;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.base.IConfigStore;

/**
 * An interface represents certificate server
 * backend database.
 * <P>
 * This interface separate the database subsystem functionalities from internal implementation.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IDBSubsystem extends ISubsystem {

    public static final String SUB_ID = "dbs";

    // values for repos
    public static final int CERTS = 0;
    public static final int REQUESTS = 1;
    public static final int REPLICA_ID = 2;
    public static final int NUM_REPOS = 3;

    /**
     * Retrieves the base DN.
     *
     * @return base DN of the subsystem
     */
    public String getBaseDN();

    /**
     * Retrieves the registry.
     *
     * @return registry
     */
    public IDBRegistry getRegistry();

    /**
     * Creates a database session.
     *
     * @return database session
     * @exception EDBException failed to create session
     */
    public IDBSSession createSession() throws EDBException;

    /**
     * Avoids losing serial number.
     *
     * @return true if serial number recovery option is enabled
     */
    public boolean enableSerialNumberRecovery();

    /**
     * Records next serial number in config file
     *
     * @param serial next serial number
     * @exception EBaseException failed to set
     */
    public void setNextSerialConfig(BigInteger serial) throws EBaseException;

    /**
     * Gets the next serial number in config file
     *
     * @return next serial number
     */
    public BigInteger getNextSerialConfig();

    /**
     * Records maximum serial number limit in config file
     *
     * @param serial max serial number
     * @param repo repo identifier
     * @exception EBaseException failed to set
     */
    public void setMaxSerialConfig(int repo, String serial) throws EBaseException;

    /**
     * Records minimum serial number limit in config file
     *
     * @param serial min serial number
     * @param repo repo identifier
     * @exception EBaseException failed to set
     */
    public void setMinSerialConfig(int repo, String serial) throws EBaseException;

    /**
     * Records maximum serial number limit for the next range in config file
     *
     * @param serial max serial number
     * @param repo repo identifier
     * @exception EBaseException failed to set
     */
    public void setNextMaxSerialConfig(int repo, String serial) throws EBaseException;

    /**
     * Records minimum serial number limit for the next range in config file
     *
     * @param serial min serial number
     * @param repo repo identifier
     * @exception EBaseException failed to set
     */
    public void setNextMinSerialConfig(int repo, String serial) throws EBaseException;

    /**
     * Gets minimum serial number limit in config file
     *
     * @param repo repo identifier
     * @return min serial number
     */
    public String getMinSerialConfig(int repo);

    /**
     * Gets the maximum serial number limit in config file
     *
     * @param repo repo identifier
     * @return max serial number
     */
    public String getMaxSerialConfig(int repo);

    /**
     * Gets the maximum serial number limit for next range in config file
     *
     * @param repo repo identifier
     * @return max serial number
     */
    public String getNextMaxSerialConfig(int repo);

    /**
     * Gets minimum serial number limit for next range in config file
     *
     * @param repo repo identifier
     * @return min serial number
     */
    public String getNextMinSerialConfig(int repo);

    /**
     * Gets low water mark limit in config file
     *
     * @param repo repo identifier
     * @return low water mark
     */
    public String getLowWaterMarkConfig(int repo);

    /**
     * Gets range increment limit for next range in config file
     *
     * @param repo repo identifier
     * @return range increment
     */
    public String getIncrementConfig(int repo);

    /**
     * Gets number corresponding to start of next range from database
     *
     * @param repo repo identifier
     * @return start of next range
     */
    public String getNextRange(int repo);

    /**
     * Determines if a range conflict has been observed in database
     *
     * @param repo repo identifier
     * @return true if range conflict, false otherwise
     */
    public boolean hasRangeConflict(int repo);

    /**
     * Determines if serial number management has been enabled
     *
     * @return true if enabled, false otherwise
     */
    public boolean getEnableSerialMgmt();

    /**
     * Sets whether serial number management is enabled for certs
     * and requests.
     *
     * @param value true/false
     * @exception EBaseException failed to set
     */
    public void setEnableSerialMgmt(boolean value) throws EBaseException;

    /**
     * Gets internal DB configuration store
     *
     * @return internal DB configuration store
     */
    public IConfigStore getConfigStore();

    /**
     * Gets DB subsystem configuration store
     *
     * @return DB subsystem configuration store
     */
    public IConfigStore getDBConfigStore();

    /**
     * Gets attribute value for specified entry
     *
     * @param dn            entry's distinguished name 
     * @param attrName      attribute's name 
     * @param defaultValue  attribute's default value 
     * @param errorValue    attribute's error value 
     * @return attribute value
     */
    public String getEntryAttribute(String dn, String attrName,
                                    String defaultValue, String errorValue);

    /**
     * Returns LDAP connection to connection pool.
     *
     * @param conn connection to be returned
     */
    public void returnConn(LDAPConnection conn);
}
