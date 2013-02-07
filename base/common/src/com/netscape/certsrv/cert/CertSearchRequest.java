//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2011 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

// TODO: This class is brute force. Come up with a way to divide these search filter entities into
// smaller classes
package com.netscape.certsrv.cert;

import java.io.Reader;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author jmagne
 *
 */
@XmlRootElement(name = "CertSearchRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertSearchRequest {

    //Serial Number
    @XmlElement
    protected boolean serialNumberRangeInUse;

    @XmlElement
    protected String serialTo;

    @XmlElement
    protected String serialFrom;

    //Subject Name
    @XmlElement
    protected boolean subjectInUse;

    @XmlElement
    protected String eMail;

    @XmlElement
    protected String commonName;

    @XmlElement
    protected String userID;

    @XmlElement
    protected String orgUnit;

    @XmlElement
    protected String org;

    @XmlElement
    protected String locality;

    @XmlElement
    protected String state;

    @XmlElement
    protected String country;

    @XmlElement
    protected boolean matchExactly;

    //Status
    @XmlElement
    protected String status;

    //Revoked By

    @XmlElement
    protected String revokedBy;

    //Revoked On

    @XmlElement
    protected String revokedOnFrom;

    @XmlElement
    protected String revokedOnTo;

    //Revocation Reason

    @XmlElement
    protected String revocationReason;

    //Issued By

    @XmlElement
    protected String issuedBy;

    //Issued On

    @XmlElement
    protected String issuedOnFrom;

    @XmlElement
    protected String issuedOnTo;

    //Valid Not Before

    @XmlElement
    protected String validNotBeforeFrom;

    @XmlElement
    protected String validNotBeforeTo;

    //Valid Not After

    @XmlElement
    protected String validNotAfterFrom;

    @XmlElement
    protected String validNotAfterTo;

    //Validity Length

    @XmlElement
    protected String validityOperation;

    @XmlElement
    protected Integer validityCount;

    @XmlElement
    protected Long validityUnit;

    // Cert Type

    @XmlElement
    protected String certTypeSubEmailCA;

    @XmlElement
    protected String certTypeSubSSLCA;

    @XmlElement
    protected String certTypeSecureEmail;

    @XmlElement
    protected String certTypeSSLClient;

    @XmlElement
    protected String certTypeSSLServer;

    //Revoked By
    @XmlElement
    protected boolean revokedByInUse;

    //Revoked On
    @XmlElement
    protected boolean revokedOnInUse;

    @XmlElement
    protected boolean revocationReasonInUse;

    @XmlElement
    protected boolean issuedByInUse;

    @XmlElement
    protected boolean issuedOnInUse;

    @XmlElement
    protected boolean validNotBeforeInUse;

    @XmlElement
    protected boolean validNotAfterInUse;

    @XmlElement
    protected boolean validityLengthInUse;

    @XmlElement
    protected boolean certTypeInUse;

    //Boolean values
    public boolean getSerialNumberRangeInUse() {
        return serialNumberRangeInUse;
    }

    public void setSerialNumberRangeInUse(boolean serialNumberRangeInUse) {
        this.serialNumberRangeInUse = serialNumberRangeInUse;
    }

    public boolean getSubjectInUse() {
        return subjectInUse;
    }

    public void setSubjectInUse(boolean subjectInUse) {
        this.subjectInUse = subjectInUse;
    }

    public boolean getRevokedByInUse() {
        return revokedByInUse;
    }

    public void setRevokedByInUse(boolean revokedByInUse) {
        this.revokedByInUse = revokedByInUse;
    }

    public boolean getRevokedOnInUse() {
        return revokedOnInUse;
    }

    public void setRevokedOnInUse(boolean revokedOnInUse) {
        this.revokedOnInUse = revokedOnInUse;
    }

    public void setRevocationReasonInUse(boolean revocationReasonInUse) {
        this.revocationReasonInUse = revocationReasonInUse;
    }

    public boolean getRevocationReasonInUse() {
        return revocationReasonInUse;
    }

    public void setIssuedByInUse(boolean issuedByInUse) {
        this.issuedByInUse = issuedByInUse;
    }

    public boolean getIssuedByInUse() {
        return issuedByInUse;
    }

    public void setIssuedOnInUse(boolean issuedOnInUse) {
        this.issuedOnInUse = issuedOnInUse;
    }

    public boolean getIssuedOnInUse() {
        return issuedOnInUse;
    }

    public void setValidNotBeforeInUse(boolean validNotBeforeInUse) {
        this.validNotBeforeInUse = validNotBeforeInUse;
    }

    public boolean getValidNotBeforeInUse() {
        return validNotBeforeInUse;
    }

    public void setValidNotAfterInUse(boolean validNotAfterInUse) {
        this.validNotAfterInUse = validNotAfterInUse;
    }

    public boolean getValidNotAfterInUse() {
        return validNotAfterInUse;
    }

    public void setValidityLengthInUse(boolean validityLengthInUse) {
        this.validityLengthInUse = validityLengthInUse;
    }

    public boolean getValidityLengthInUse() {
        return validityLengthInUse;
    }

    public void setCertTypeInUse(boolean certTypeInUse) {
        this.certTypeInUse = certTypeInUse;
    }

    public boolean getCertTypeInUse() {
        return certTypeInUse;
    }

    //Actual Values

    public String getSerialTo() {
        return serialTo;
    }

    public void setSerialTo(String serialTo) {
        this.serialTo = serialTo;
    }

    public String getSerialFrom() {
        return serialFrom;
    }

    public void setSerialFrom(String serialFrom) {
        this.serialFrom = serialFrom;
    }

    //Subject Name

    public String getEmail() {
        return eMail;
    }

    public void setEmail(String email) {
        this.eMail = email;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getOrgUnit() {
        return orgUnit;
    }

    public void setOrgUnit(String orgUnit) {
        this.orgUnit = orgUnit;
    }

    public String getOrg() {
        return org;
    }

    public void setOrg(String org) {
        this.org = org;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public boolean getMatchExactly() {
        return matchExactly;
    }

    public void setMatchExactly(boolean matchExactly) {
        this.matchExactly = matchExactly;
    }

    //Status

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    //Revoked On

    public String getRevokedOnTo() {
        return revokedOnTo;
    }

    public void setRevokedOnTo(String revokedOnTo) {
        this.revokedOnTo = revokedOnTo;
    }

    public String getRevokedOnFrom() {
        return revokedOnFrom;
    }

    public void setRevokedOnFrom(String revokedOnFrom) {
        this.revokedOnFrom = revokedOnFrom;
    }

    //Revoked By

    public String getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(String revokedBy) {
        this.revokedBy = revokedBy;
    }

    //Revocation Reason

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    //Issued By

    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    //Issued On

    public String getIssuedOnFrom() {
        return issuedOnFrom;
    }

    public void setIssuedOnFrom(String issuedOnFrom) {
        this.issuedOnFrom = issuedOnFrom;
    }

    public String getIssuedOnTo() {
        return issuedOnTo;
    }

    public void setIssuedOnTo(String issuedOnTo) {
        this.issuedOnTo = issuedOnTo;
    }

    //Valid Not After

    public String getValidNotAfterFrom() {
        return validNotAfterFrom;
    }

    public void setValidNotAfterFrom(String validNotAfterFrom) {
        this.validNotAfterFrom = validNotAfterFrom;
    }

    public String getValidNotAfterTo() {
        return validNotAfterTo;
    }

    public void setValidNotAfterTo(String validNotAfterTo) {
        this.validNotAfterTo = validNotAfterTo;
    }

    //Valid Not Before

    public String getValidNotBeforeFrom() {
        return validNotBeforeFrom;
    }

    public void setValidNotBeforeFrom(String validNotBeforeFrom) {
        this.validNotBeforeFrom = validNotBeforeFrom;
    }

    public String getValidNotBeforeTo() {
        return validNotBeforeTo;
    }

    public void setValidNotBeforeTo(String validNotBeforeTo) {
        this.validNotBeforeTo = validNotBeforeTo;
    }

    //Validity Length

    public String getValidityOperation() {
        return validityOperation;
    }

    public void setValidityOperation(String validityOperation) {
        this.validityOperation = validityOperation;
    }

    public Long getValidityUnit() {
        return validityUnit;
    }

    public void setValidityUnit(Long validityUnit) {
        this.validityUnit = validityUnit;
    }

    public Integer getValidityCount() {
        return validityCount;
    }

    public void setValidityCount(Integer validityCount) {
        this.validityCount = validityCount;
    }

    //Cert Type

    public String getCertTypeSubEmailCA() {
        return certTypeSubEmailCA;
    }

    public void setCertTypeSubEmailCA(String certTypeSubEmailCA) {
        this.certTypeSubEmailCA = certTypeSubEmailCA;
    }

    public String getCertTypeSubSSLCA() {
        return certTypeSubSSLCA;
    }

    public void setCertTypeSubSSLCA(String certTypeSubSSLCA) {
        this.certTypeSubSSLCA = certTypeSubSSLCA;
    }

    public String getCertTypeSecureEmail() {
        return certTypeSecureEmail;
    }

    public void setCertTypeSecureEmail(String certTypeSecureEmail) {
        this.certTypeSecureEmail = certTypeSecureEmail;
    }

    public String getCertTypeSSLClient() {
        return certTypeSSLClient;
    }

    public void setCertTypeSSLClient(String SSLClient) {
        this.certTypeSSLClient = SSLClient;
    }

    public String getCertTypeSSLServer() {
        return certTypeSSLServer;
    }

    public void setCertTypeSSLServer(String SSLServer) {
        this.certTypeSSLServer = SSLServer;
    }

    public CertSearchRequest() {
        // required for JAXB (defaults)
    }

    public void buildFromServletRequest(HttpServletRequest req) {
        //Set values from the servlet request
        if (req == null) {
            return;
        }
    }

    public CertSearchRequest(MultivaluedMap<String, String> form) {
    }

    public static CertSearchRequest valueOf(Reader reader) throws JAXBException {
        JAXBContext context = JAXBContext.newInstance(CertSearchRequest.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        return (CertSearchRequest) unmarshaller.unmarshal(reader);
    }
}
