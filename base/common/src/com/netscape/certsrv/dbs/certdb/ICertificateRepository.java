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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import netscape.ldap.LDAPEntry;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.dbs.repository.IRepository;

/**
 * An interface represents a CMS certificate repository.
 * It stores all the issued certificate.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ICertificateRepository extends IRepository {

    /**
     * Retrieves the next certificate serial number, and also increases
     * the serial number by one.
     *
     * @return serial number
     * @exception EBaseException failed to retrieve next serial number
     */
    public BigInteger getNextSerialNumber()
            throws EBaseException;

    /**
     * Adds a certificate record to the repository. Each certificate
     * record contains four parts: certificate, meta-attributes,
     * issue information and reovcation information.
     * <P>
     *
     * @param record X.509 certificate
     * @exception EBaseException failed to add new certificate to
     *                the repository
     */
    public void addCertificateRecord(ICertRecord record)
            throws EBaseException;

    /**
     * Reads the certificate identified by the given serial no.
     *
     * @param serialNo serial number of certificate
     * @return certificate
     * @exception EBaseException failed to retrieve certificate
     */
    public X509CertImpl getX509Certificate(BigInteger serialNo)
            throws EBaseException;

    /**
     * Reads certificate from repository.
     *
     * @param serialNo serial number of certificate
     * @return certificate record
     * @exception EBaseException failed to retrieve certificate
     */
    public ICertRecord readCertificateRecord(BigInteger serialNo)
            throws EBaseException;

    /**
     * Sets certificate status update internal
     *
     * @param requestRepo request repository
     * @param interval update interval
     * @param listenToCloneModifications enable listening to clone modifications
     */
    public void setCertStatusUpdateInterval(IRepository requestRepo,
            int interval,
            boolean listenToCloneModifications);

    /**
     * Updates certificate status now. This is a blocking method.
     *
     * @exception EBaseException failed to update
     */
    public void updateCertStatus() throws EBaseException;

    /**
     * Modifies certificate record.
     *
     * @param serialNo serial number of record
     * @param mods modifications
     * @exception EBaseException failed to modify
     */
    public void modifyCertificateRecord(BigInteger serialNo,
            ModificationSet mods) throws EBaseException;

    /**
     * Checks if the certificate exists in this repository.
     *
     * @param serialNo serial number of certificate
     * @return true if it exists
     * @exception EBaseException failed to check
     */
    public boolean containsCertificate(BigInteger serialNo)
            throws EBaseException;

    /**
     * Deletes certificate from this repository.
     *
     * @param serialNo serial number of certificate
     * @exception EBaseException failed to delete
     */
    public void deleteCertificateRecord(BigInteger serialNo)
            throws EBaseException;

    /**
     * Marks certificate as revoked.
     *
     * @param id serial number
     * @param info revocation information
     * @exception EBaseException failed to mark
     */
    public void markAsRevoked(BigInteger id, IRevocationInfo info)
            throws EBaseException;

    /**
     * Updates certificate status.
     *
     * @param id serial number
     * @param status certificate status
     * @exception EBaseException failed to update status
     */
    public void updateStatus(BigInteger id, String status)
            throws EBaseException;

    /**
     * Marks certificate as renewable.
     *
     * @param record certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewable(ICertRecord record)
            throws EBaseException;

    /**
     * Marks certificate as not renewable.
     *
     * @param record certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsNotRenewable(ICertRecord record)
            throws EBaseException;

    /**
     * Marks certificate as renewed.
     *
     * @param serialNo certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewed(String serialNo)
            throws EBaseException;

    /**
     * Marks certificate as renewed and notified.
     *
     * @param serialNo certificate record to modify
     * @exception EBaseException failed to update
     */
    public void markCertificateAsRenewalNotified(String serialNo)
            throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     * Here is a list of filter
     * attribute can be used:
     *
     * <pre>
     *   certRecordId
     *   certMetaInfo
     *   certStatus
     *   certCreateTime
     *   certModifyTime
     *   x509Cert.notBefore
     *   x509Cert.notAfter
     *   x509Cert.subject
     * </pre>
     *
     * The filter should follow RFC1558 LDAP filter syntax.
     * For example,
     *
     * <pre>
     *   (&(certRecordId=5)(x509Cert.notBefore=934398398))
     * </pre>
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<Object> searchCertificates(String filter, int maxSize)
            throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param maxSize max size to return
     * @param timeLimit timeout value
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<ICertRecord> searchCertificates(String filter, int maxSize,
            int timeLimit) throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public ICertRecordList findCertRecordsInList(String filter,
            String attrs[], int pageSize) throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public ICertRecordList findCertRecordsInList(String filter,
            String attrs[], String sortKey, int pageSize)
            throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param jumpTo jump to index
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public ICertRecordList findCertRecordsInList(String filter,
            String attrs[], String jumpTo, String sortKey, int pageSize)
            throws EBaseException;

    public ICertRecordList findCertRecordsInList(String filter,
            String attrs[], String jumpTo, boolean hardJumpTo, String sortKey, int pageSize)
            throws EBaseException;

    /**
     * Finds a list of certificate records that satisifies
     * the filter.
     *
     * @param filter search filter
     * @param attrs selected attribute
     * @param jumpTo jump to index
     * @param sortKey key to use for sorting the returned elements
     * @param pageSize page size
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public ICertRecordList findCertRecordsInListRawJumpto(String filter,
            String attrs[], String jumpTo, String sortKey, int pageSize)
            throws EBaseException;

    public static final int ALL_CERTS = 0;
    public static final int ALL_VALID_CERTS = 1;
    public static final int ALL_UNREVOKED_CERTS = 2;

    /**
     * Gets all valid and unexpired certificates pertaining
     * to a subject DN.
     *
     * @param subjectDN The distinguished name of the subject.
     * @param validityType The type of certificatese to retrieve.
     * @return An array of certificates.
     * @throws EBaseException on error.
     */
    public X509CertImpl[] getX509Certificates(String subjectDN,
            int validityType) throws EBaseException;

    /**
     * Retrieves all the revoked certificates that have not expired.
     *
     * @param asOfDate as of date
     * @return a list of revoked certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getRevokedCertificates(Date asOfDate)
            throws EBaseException;

    /**
     * Retrieves all revoked certificates including ones that have expired
     * or that are not yet valid.
     *
     * @return a list of revoked certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<ICertRecord> getAllRevokedCertificates()
            throws EBaseException;

    /**
     * Retrieves all revoked but not expired certificates.
     *
     * @return a list of revoked certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<ICertRecord> getAllRevokedNonExpiredCertificates()
            throws EBaseException;

    /**
     * Finds all certificates given a filter.
     *
     * @param filter search filter
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<X509CertImpl> findCertificates(String filter)
            throws EBaseException;

    /**
     * Finds all certificate records given a filter.
     *
     * @param filter search filter
     * @return a list of certificates
     * @exception EBaseException failed to search
     */
    public Enumeration<ICertRecord> findCertRecords(String filter)
            throws EBaseException;

    /**
     * Gets Revoked certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public ICertRecordList getRevokedCertsByNotAfterDate(Date date,
            int pageSize) throws EBaseException;

    /**
     * Gets Invalid certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public ICertRecordList getInvalidCertsByNotBeforeDate(Date date,
            int pageSize) throws EBaseException;

    /**
     * Gets valid certs orderes by noAfter date, jumps to records
     * where notAfter date is greater than current.
     *
     * @param date reference date
     * @param pageSize page size
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve
     */
    public ICertRecordList getValidCertsByNotAfterDate(Date date,
            int pageSize) throws EBaseException;

    /**
     * Creates certificate record.
     *
     * @param id serial number
     * @param cert certificate
     * @param meta meta information
     * @return certificate record
     */
    public ICertRecord createCertRecord(BigInteger id,
            Certificate cert, MetaInfo meta);

    /**
     * Finds certificate records.
     *
     * @param filter search filter
     * @return a list of certificate records
     * @exception EBaseException failed to retrieve cert records
     */
    public Enumeration<Object> findCertRecs(String filter)
            throws EBaseException;

    /**
     * Retrieves renewable certificates.
     *
     * @param renewalTime renewal time
     * @return certificates
     * @exception EBaseException failed to retrieve
     */
    public Hashtable<String, RenewableCertificateCollection> getRenewableCertificates(String renewalTime)
            throws EBaseException;

    /**
     * Unmark a revoked certificates.
     *
     * @param id serial number
     * @param info revocation information
     * @param revokedOn revocation date
     * @param revokedBy userid
     * @exception EBaseException failed to unmark
     */
    public void unmarkRevoked(BigInteger id, IRevocationInfo info,
            Date revokedOn, String revokedBy)
            throws EBaseException;

    /**
     * Retrieves valid and not published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getValidNotPublishedCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves expired and published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getExpiredPublishedCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves revoked and published certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getRevokedPublishedCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves valid certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getValidCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves expired certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getExpiredCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves revoked certificates.
     *
     * @param from starting serial number
     * @param to ending serial number
     * @return a list of certificates
     * @exception EBaseException failed to retrieve
     */
    public Enumeration<ICertRecord> getRevokedCertificates(String from, String to)
            throws EBaseException;

    /**
     * Retrieves modified certificate records.
     *
     * @param entry LDAPEntry with modified data
     */
    public void getModifications(LDAPEntry entry);

    /**
     * Removes certificate records with this repository.
     *
     * @param beginS BigInteger with radix 16
     * @param endS BigInteger with radix 16
     */
    public void removeCertRecords(BigInteger beginS, BigInteger endS) throws EBaseException;

    /**
     * Retrieves serial number management mode.
     *
     * @return serial number management mode,
     * "true" indicates random serial number management,
     * "false" indicates sequential serial number management.
     */
    public boolean getEnableRandomSerialNumbers();

    /**
     * Sets serial number management mode for certificates..
     *
     * @param random "true" sets random serial number management, "false" sequential
     * @param updateMode "true" updates "description" attribute in certificate repository
     * @param forceModeChange "true" forces certificate repository mode change
     */
    public void setEnableRandomSerialNumbers(boolean random, boolean updateMode, boolean forceModeChange);

    public void shutdown();
}
