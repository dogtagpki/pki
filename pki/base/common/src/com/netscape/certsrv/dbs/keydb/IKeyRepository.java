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

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Enumeration;

import netscape.security.x509.X500Name;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepository;

/**
 * An interface represents a Key repository. This is the
 * container of archived keys.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IKeyRepository extends IRepository {

    /**
     * Archives a key to the repository.
     * <P>
     * 
     * @param record key record
     * @exception EBaseException failed to archive key
     */
    public void addKeyRecord(IKeyRecord record) throws EBaseException;

    /**
     * Reads an archived key by serial number.
     * <P>
     * 
     * @param serialNo serial number
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public IKeyRecord readKeyRecord(BigInteger serialNo)
            throws EBaseException;

    /**
     * Reads an archived key by b64 encoded cert.
     * <P>
     * 
     * @param cert b64 encoded cert
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public IKeyRecord readKeyRecord(String cert)
            throws EBaseException;

    /**
     * Reads an archived key by owner name.
     * <P>
     * 
     * @param ownerName owner name
     * @return key record
     * @exception EBaseException failed to recover key
     */
    public IKeyRecord readKeyRecord(X500Name ownerName)
            throws EBaseException;

    /**
     * Reads archived key using public key.
     * 
     * @param publicKey public key that is corresponding
     *            to the private key
     * @return key record
     * @exception EBaseException failed to read key
     */
    public IKeyRecord readKeyRecord(PublicKey publicKey)
            throws EBaseException;

    /**
     * Searches for private keys.
     * 
     * @param filter LDAP filter for the search
     * @param maxSize maximium number of entries to be returned
     * @return a list of private key records
     * @exception EBaseException failed to search keys
     */
    public Enumeration<IKeyRecord> searchKeys(String filter, int maxSize)
            throws EBaseException;

    /**
     * Searches for private keys.
     * 
     * @param filter LDAP filter for the search
     * @param maxSize maximium number of entries to be returned
     * @param timeLimt timeout value
     * @return a list of private key records
     * @exception EBaseException failed to search keys
     */
    public Enumeration<IKeyRecord> searchKeys(String filter, int maxSize, int timeLimt)
            throws EBaseException;

    /**
     * Deletes a key record.
     * 
     * @param serialno key identifier
     * @exception EBaseException failed to delete key record
     */
    public void deleteKeyRecord(BigInteger serialno)
            throws EBaseException;

    /**
     * Modifies key record in this repository.
     * 
     * @param serialNo key identifier
     * @param mods modification of key records
     * @exception EBaseException failed to modify key record
     */
    public void modifyKeyRecord(BigInteger serialNo,
            ModificationSet mods) throws EBaseException;

    /**
     * Searchs for a list of key records.
     * Here is a list of supported filter attributes:
     * 
     * <pre>
     *   keySerialNumber
     *   keyState
     *   algorithm
     *   keySize
     *   keyOwnerName
     *   privateKey
     *   publicKey
     *   dateOfRecovery
     *   keyCreateTime
     *   keyModifyTime
     *   keyMetaInfo
     * </pre>
     * 
     * @param filter search filter
     * @param attrs list of attributes to be returned
     * @param pageSize virtual list page size
     * @return list of key records
     * @exception EBaseException failed to search key records
     */
    public IKeyRecordList findKeyRecordsInList(String filter,
            String attrs[], int pageSize) throws EBaseException;

    /**
     * Searchs for a list of key records.
     * 
     * @param filter search filter
     * @param attrs list of attributes to be returned
     * @param sortKey name of attribute that the list should be sorted by
     * @param pageSize virtual list page size
     * @return list of key records
     * @exception EBaseException failed to search key records
     */
    public IKeyRecordList findKeyRecordsInList(String filter,
            String attrs[], String sortKey, int pageSize)
            throws EBaseException;
}
