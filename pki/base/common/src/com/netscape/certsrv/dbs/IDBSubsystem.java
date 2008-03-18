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


import java.math.*;
import netscape.ldap.*;
import com.netscape.certsrv.base.*;


/**
 * An interface represents certificate server
 * backend database.
 * <P>
 * This interface separate the database subsystem
 * functionalities from internal implementation.
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $ 
 */
public interface IDBSubsystem extends ISubsystem {

    public static final String SUB_ID = "dbs";

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
     * @exception EBaseException failed to set 
     */
    public void setMaxSerialConfig(String serial) throws EBaseException;


    public String getMinSerialConfig();

    /**
     * Gets the maximum serial number limit in config file
     *
     * @return max serial number
     */
    public String getMaxSerialConfig();


    public String getMinRequestConfig();
 
    public String getMaxRequestConfig();


    /**
     * Returns LDAP connection to connection pool.
     *
     * @param conn connection to be returned
     */
    public void returnConn(LDAPConnection conn);
}
