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


import java.util.*;
import java.math.*;
import com.netscape.certsrv.base.*;


/**
 * An interface contains constants for key record.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IKeyRecord {
    public static final String ATTR_ID = "keySerialNumber";
    public static final String ATTR_STATE = "keyState";
    public static final String ATTR_ALGORITHM = "algorithm";
    public static final String ATTR_KEY_SIZE = "keySize";
    public static final String ATTR_OWNER_NAME = "keyOwnerName";
    public static final String ATTR_PRIVATE_KEY_DATA = "privateKey";
    public static final String ATTR_PUBLIC_KEY_DATA = "publicKey";
    public static final String ATTR_DATE_OF_RECOVERY = "dateOfRecovery";
    public static final String ATTR_CREATE_TIME = "keyCreateTime";
    public static final String ATTR_MODIFY_TIME = "keyModifyTime";
    public static final String ATTR_META_INFO = "keyMetaInfo";
    public static final String ATTR_ARCHIVED_BY = "keyArchivedBy";
    
    // key state
    public static final String STATUS_ANY = "ANY";
    public static final String STATUS_VALID = "VALID";
    public static final String STATUS_INVALID = "INVALID";
    
    /**
     * Retrieves the state of the key.
     *
     * @return key state
     * @exception EBaseException failed to retrieve state of the key
     */
    public KeyState getState() throws EBaseException;

    /**
     * Retrieves key identifier.
     *
     * @return key id
     * @exception EBaseException failed to retrieve key id
     */
    public BigInteger getSerialNumber() throws EBaseException; 

    /**
     * Retrieves key owner name.
     *
     * @return key owner name
     * @exception EBaseException failed to retrieve key owner name
     */
    public String getOwnerName() throws EBaseException;

    /**
     * Retrieves key algorithm.
     *
     * @return key algorithm
     */
    public String getAlgorithm(); 

    /**
     * Retrieves key length.
     *
     * @return key length
     * @exception EBaseException failed to retrieve key length
     */
    public Integer getKeySize() throws EBaseException; 

    /**
     * Retrieves archiver identifier.
     *
     * @return archiver uid
     */
    public String getArchivedBy(); 

    /**
     * Retrieves creation time.
     *
     * @return creation time
     */
    public Date getCreateTime(); 

    /**
     * Retrieves last modification time.
     *
     * @return modification time
     */
    public Date getModifyTime(); 

    /**
     * Retrieves dates of recovery.
     *
     * @return recovery history
     * @exception EBaseException failed to retrieve recovery history
     */
    public Date[] getDateOfRevocation() throws EBaseException; 

    /**
     * Retrieves public key data.
     *
     * @return public key data
     * @exception EBaseException failed to retrieve public key data
     */
    public byte[] getPublicKeyData() throws EBaseException;
}    
