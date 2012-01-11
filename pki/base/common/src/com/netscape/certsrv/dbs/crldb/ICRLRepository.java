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
package com.netscape.certsrv.dbs.crldb;

import java.math.BigInteger;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.ModificationSet;

/**
 * An interface represents a CMS CRL repository. It stores
 * all the CRL issuing points.
 * 
 * @version $Revision$, $Date$
 */
public interface ICRLRepository {

    /**
     * Adds CRL issuing point record.
     * 
     * @param rec issuing point record
     * @exception EBaseException failed to add new issuing point record
     */
    public void addCRLIssuingPointRecord(ICRLIssuingPointRecord rec)
            throws EBaseException;

    /**
     * Retrieves all the issuing points' names.
     * 
     * @return A list of issuing points' names.
     * @exception EBaseException failed to retrieve all the issuing points' names.
     */
    public Vector getIssuingPointsNames() throws EBaseException;

    /**
     * Reads issuing point record.
     * 
     * @return issuing point record
     * @exception EBaseException failed to read issuing point record
     */
    public ICRLIssuingPointRecord readCRLIssuingPointRecord(String id)
            throws EBaseException;

    /**
     * Deletes issuing point record.
     * 
     * @param id issuing point record id
     * @exception EBaseException failed to delete issuing point record
     */
    public void deleteCRLIssuingPointRecord(String id)
            throws EBaseException;

    /**
     * Modifies issuing point record.
     * 
     * @param id issuing point record id
     * @param mods set of modifications
     * @exception EBaseException failed to modify issuing point record
     */
    public void modifyCRLIssuingPointRecord(String id, ModificationSet mods)
            throws EBaseException;

    /**
     * Updates CRL issuing point record.
     * 
     * @param id issuing point record id
     * @param newCRL encoded binary CRL
     * @param thisUpdate time of this update
     * @param nextUpdate time of next update
     * @param crlNumber CRL number
     * @param crlSize CRL size
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLIssuingPointRecord(String id, byte[] newCRL,
            Date thisUpdate, Date nextUpdate, BigInteger crlNumber, Long crlSize)
            throws EBaseException;

    /**
     * Updates CRL issuing point record.
     * 
     * @param id issuing point record id
     * @param newCRL encoded binary CRL
     * @param thisUpdate time of this update
     * @param nextUpdate time of next update
     * @param crlNumber CRL number
     * @param crlSize CRL size
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLIssuingPointRecord(String id, byte[] newCRL,
            Date thisUpdate, Date nextUpdate, BigInteger crlNumber, Long crlSize,
            Hashtable revokedCerts, Hashtable unrevokedCerts, Hashtable expiredCerts)
            throws EBaseException;

    /**
     * Updates CRL issuing point record.
     * 
     * @param id issuing point record id
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateRevokedCerts(String id, Hashtable revokedCerts, Hashtable unrevokedCerts)
            throws EBaseException;

    /**
     * Updates CRL issuing point record.
     * 
     * @param id issuing point record id
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateExpiredCerts(String id, Hashtable expiredCerts)
            throws EBaseException;

    /**
     * Updates CRL issuing point record.
     * 
     * @param id issuing point record id
     * @param crlSize CRL size
     * @param revokedCerts list of revoked certificates
     * @param unrevokedCerts list of released from hold certificates
     * @param expiredCerts list of expired certificates
     * @exception EBaseException failed to update issuing point record
     */
    public void updateCRLCache(String id, Long crlSize,
            Hashtable revokedCerts,
            Hashtable unrevokedCerts,
            Hashtable expiredCerts)
            throws EBaseException;

    /**
     * Updates CRL issuing point record with delta-CRL.
     * 
     * @param id issuing point record id
     * @param deltaCRLNumber delta CRL number
     * @param deltaCRLSize delta CRL size
     * @param nextUpdate time of next update
     * @param deltaCRL delta CRL in binary form
     * @exception EBaseException failed to update issuing point record
     */
    public void updateDeltaCRL(String id, BigInteger deltaCRLNumber,
                               Long deltaCRLSize, Date nextUpdate,
                               byte[] deltaCRL)
            throws EBaseException;

    /**
     * Updates CRL issuing point record with reference to the first
     * unsaved data.
     * 
     * @param id issuing point record id
     * @param firstUnsaved reference to the first unsaved data
     * @exception EBaseException failed to update issuing point record
     */
    public void updateFirstUnsaved(String id, String firstUnsaved)
            throws EBaseException;
}
