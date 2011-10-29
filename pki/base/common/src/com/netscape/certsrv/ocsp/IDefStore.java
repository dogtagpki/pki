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
package com.netscape.certsrv.ocsp;


import java.util.*;
import java.math.*;
import java.security.cert.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.dbs.repository.*;
import com.netscape.cmsutil.ocsp.*;


/**
 * This class defines an Online Certificate Status Protocol (OCSP) store which
 * has been extended to provide information from the internal database.
 * <P> 
 *
 * @version $Revision$, $Date$
 */
public interface IDefStore extends IOCSPStore
{
    /**
     * This method retrieves the number of CRL updates since startup.
     * <P>
     *
     * @return count the number of OCSP default stores
     */
    public int getStateCount(); 

    /**
     * This method retrieves the number of OCSP requests since startup.
     * <P>
     *
     * @param id a string associated with an OCSP request
     * @return count the number of this type of OCSP requests
     */
    public long getReqCount(String id);

    /**
     * This method creates a an OCSP default store repository record.
     * <P>
     *
     * @return IRepositoryRecord an instance of the repository record object
     */
    public IRepositoryRecord createRepositoryRecord(); 

    /**
     * This method adds a request to the default OCSP store repository.
     * <P>
     *
     * @param name a string representing the name of this request
     * @param thisUpdate the current request
     * @param rec an instance of the repository record object
     * @exception EBaseException occurs when there is an error attempting to
     *    add this request to the repository
     */
    public void addRepository(String name, String thisUpdate,
        IRepositoryRecord rec)
        throws EBaseException;

    /**
     * This method specifies whether or not to wait for the Certificate
     * Revocation List (CRL) to be updated.
     * <P>
     *
     * @return boolean true or false
     */
    public boolean waitOnCRLUpdate();

    /**
     * This method updates the specified CRL.
     * <P>
     *
     * @param crl the CRL to be updated
     * @exception EBaseException occurs when the CRL cannot be updated
     */
    public void updateCRL(X509CRL crl) throws EBaseException;

    /**
     * This method attempts to read the CRL issuing point.
     * <P>
     *
     * @param name the name of the CRL to be read
     * @return ICRLIssuingPointRecord the CRL issuing point
     * @exception EBaseException occurs when the specified CRL cannot be located
     */
    public ICRLIssuingPointRecord readCRLIssuingPoint(String name)
        throws EBaseException;

    /**
     * This method searches all CRL issuing points.
     * <P>
     *
     * @param maxSize specifies the largest number of hits from the search
     * @return Enumeration a list of the CRL issuing points
     * @exception EBaseException occurs when no CRL issuing point exists
     */
    public Enumeration searchAllCRLIssuingPointRecord(
        int maxSize)
        throws EBaseException;

    /**
     * This method searches all CRL issuing points constrained by the specified
     * filtering mechanism.
     * <P>
     *
     * @param filter a string which constrains the search
     * @param maxSize specifies the largest number of hits from the search
     * @return Enumeration a list of the CRL issuing points
     * @exception EBaseException occurs when no CRL issuing point exists
     */
    public Enumeration searchCRLIssuingPointRecord(String filter,
        int maxSize)
        throws EBaseException;

    /**
     * This method creates a CRL issuing point record.
     * <P>
     *
     * @param name a string representation of this CRL issuing point record
     * @param crlNumber the number of this CRL issuing point record
     * @param crlSize the size of this CRL issuing point record
     * @param thisUpdate the time for this CRL issuing point record
     * @param nextUpdate the time for the next CRL issuing point record
     * @return ICRLIssuingPointRecord this CRL issuing point record
     */
    public ICRLIssuingPointRecord createCRLIssuingPointRecord(
        String name, BigInteger crlNumber, 
        Long crlSize, Date thisUpdate, Date nextUpdate);

    /**
     * This method adds a CRL issuing point
     * <P>
     *
     * @param name a string representation of this CRL issuing point record
     * @param rec this CRL issuing point record
     * @exception EBaseException occurs when the specified CRL issuing point
     *     record cannot be added
     */
    public void addCRLIssuingPoint(String name, ICRLIssuingPointRecord rec)
        throws EBaseException;

    /**
     * This method deletes a CRL issuing point record
     * <P>
     *
     * @param id a string representation of this CRL issuing point record
     * @exception EBaseException occurs when the specified CRL issuing point
     *     record cannot be deleted 
     */
    public void deleteCRLIssuingPointRecord(String id)
        throws EBaseException;

    /**
     * This method checks to see if the OCSP response should return good
     * when the certificate is not found.
     * <P>
     *
     * @return boolean true or false
     */
    public boolean isNotFoundGood();
}

