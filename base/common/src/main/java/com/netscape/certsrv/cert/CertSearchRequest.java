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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Map;
import java.util.Objects;

import jakarta.ws.rs.core.MultivaluedMap;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author jmagne
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertSearchRequest implements JSONSerializer {

    protected String issuerDN;

    //Serial Number

    protected boolean serialNumberRangeInUse;
    protected String serialTo;
    protected String serialFrom;

    //Subject Name

    protected boolean subjectInUse;
    protected String eMail;
    protected String commonName;
    protected String userID;
    protected String orgUnit;
    protected String org;
    protected String locality;
    protected String state;
    protected String country;
    protected boolean matchExactly;

    //Status

    protected String status;

    //Revoked By

    protected String revokedBy;

    //Revoked On

    protected String revokedOnFrom;
    protected String revokedOnTo;

    //Revocation Reason

    protected String revocationReason;

    //Issued By

    protected String issuedBy;

    //Issued On

    protected String issuedOnFrom;
    protected String issuedOnTo;

    //Valid Not Before

    protected String validNotBeforeFrom;
    protected String validNotBeforeTo;

    //Valid Not After

    protected String validNotAfterFrom;
    protected String validNotAfterTo;

    //Validity Length

    protected String validityOperation;
    protected Integer validityCount;
    protected Long validityUnit;

    // Cert Type

    protected String certTypeSubEmailCA;
    protected String certTypeSubSSLCA;
    protected String certTypeSecureEmail;
    protected String certTypeSSLClient;
    protected String certTypeSSLServer;

    //Revoked By

    protected boolean revokedByInUse;

    //Revoked On

    protected boolean revokedOnInUse;
    protected boolean revocationReasonInUse;
    protected boolean issuedByInUse;
    protected boolean issuedOnInUse;
    protected boolean validNotBeforeInUse;
    protected boolean validNotAfterInUse;
    protected boolean validityLengthInUse;
    protected boolean certTypeInUse;

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

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
    }

    public CertSearchRequest(MultivaluedMap<String, String> form) {
    }

    @Override
    public int hashCode() {
        return Objects.hash(certTypeInUse, certTypeSSLClient, certTypeSSLServer, certTypeSecureEmail,
                certTypeSubEmailCA, certTypeSubSSLCA, commonName, country, eMail, issuedBy, issuedByInUse, issuedOnFrom,
                issuedOnInUse, issuedOnTo, issuerDN, locality, matchExactly, org, orgUnit, revocationReason,
                revocationReasonInUse, revokedBy, revokedByInUse, revokedOnFrom, revokedOnInUse, revokedOnTo,
                serialFrom, serialNumberRangeInUse, serialTo, state, status, subjectInUse, userID, validNotAfterFrom,
                validNotAfterInUse, validNotAfterTo, validNotBeforeFrom, validNotBeforeInUse, validNotBeforeTo,
                validityCount, validityLengthInUse, validityOperation, validityUnit);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertSearchRequest other = (CertSearchRequest) obj;
        return certTypeInUse == other.certTypeInUse && Objects.equals(certTypeSSLClient, other.certTypeSSLClient)
                && Objects.equals(certTypeSSLServer, other.certTypeSSLServer)
                && Objects.equals(certTypeSecureEmail, other.certTypeSecureEmail)
                && Objects.equals(certTypeSubEmailCA, other.certTypeSubEmailCA)
                && Objects.equals(certTypeSubSSLCA, other.certTypeSubSSLCA)
                && Objects.equals(commonName, other.commonName) && Objects.equals(country, other.country)
                && Objects.equals(eMail, other.eMail) && Objects.equals(issuedBy, other.issuedBy)
                && issuedByInUse == other.issuedByInUse && Objects.equals(issuedOnFrom, other.issuedOnFrom)
                && issuedOnInUse == other.issuedOnInUse && Objects.equals(issuedOnTo, other.issuedOnTo)
                && Objects.equals(issuerDN, other.issuerDN) && Objects.equals(locality, other.locality)
                && matchExactly == other.matchExactly && Objects.equals(org, other.org)
                && Objects.equals(orgUnit, other.orgUnit) && Objects.equals(revocationReason, other.revocationReason)
                && revocationReasonInUse == other.revocationReasonInUse && Objects.equals(revokedBy, other.revokedBy)
                && revokedByInUse == other.revokedByInUse && Objects.equals(revokedOnFrom, other.revokedOnFrom)
                && revokedOnInUse == other.revokedOnInUse && Objects.equals(revokedOnTo, other.revokedOnTo)
                && Objects.equals(serialFrom, other.serialFrom)
                && serialNumberRangeInUse == other.serialNumberRangeInUse && Objects.equals(serialTo, other.serialTo)
                && Objects.equals(state, other.state) && Objects.equals(status, other.status)
                && subjectInUse == other.subjectInUse && Objects.equals(userID, other.userID)
                && Objects.equals(validNotAfterFrom, other.validNotAfterFrom)
                && validNotAfterInUse == other.validNotAfterInUse
                && Objects.equals(validNotAfterTo, other.validNotAfterTo)
                && Objects.equals(validNotBeforeFrom, other.validNotBeforeFrom)
                && validNotBeforeInUse == other.validNotBeforeInUse
                && Objects.equals(validNotBeforeTo, other.validNotBeforeTo)
                && Objects.equals(validityCount, other.validityCount)
                && validityLengthInUse == other.validityLengthInUse
                && Objects.equals(validityOperation, other.validityOperation)
                && Objects.equals(validityUnit, other.validityUnit);
    }

    public Element toDOM(Document document) {

        Element requestElement = document.createElement("CertSearchRequest");

        if (issuerDN != null) {
            Element issuerDNElement = document.createElement("issuerDN");
            issuerDNElement.appendChild(document.createTextNode(issuerDN));
            requestElement.appendChild(issuerDNElement);
        }

        Element issuerDNElement = document.createElement("serialNumberRangeInUse");
        issuerDNElement.appendChild(document.createTextNode(Boolean.toString(serialNumberRangeInUse)));
        requestElement.appendChild(issuerDNElement);

        if (serialTo != null) {
            Element serialToElement = document.createElement("serialTo");
            serialToElement.appendChild(document.createTextNode(serialTo));
            requestElement.appendChild(serialToElement);
        }

        if (serialFrom != null) {
            Element serialFromElement = document.createElement("serialFrom");
            serialFromElement.appendChild(document.createTextNode(serialFrom));
            requestElement.appendChild(serialFromElement);
        }

        Element subjectInUseElement = document.createElement("subjectInUse");
        subjectInUseElement.appendChild(document.createTextNode(Boolean.toString(subjectInUse)));
        requestElement.appendChild(subjectInUseElement);

        if (eMail != null) {
            Element eMailElement = document.createElement("eMail");
            eMailElement.appendChild(document.createTextNode(eMail));
            requestElement.appendChild(eMailElement);
        }

        if (commonName != null) {
            Element commonNameElement = document.createElement("commonName");
            commonNameElement.appendChild(document.createTextNode(commonName));
            requestElement.appendChild(commonNameElement);
        }

        if (userID != null) {
            Element userIDElement = document.createElement("userID");
            userIDElement.appendChild(document.createTextNode(userID));
            requestElement.appendChild(userIDElement);
        }

        if (orgUnit != null) {
            Element orgUnitElement = document.createElement("orgUnit");
            orgUnitElement.appendChild(document.createTextNode(orgUnit));
            requestElement.appendChild(orgUnitElement);
        }

        if (org != null) {
            Element orgElement = document.createElement("org");
            orgElement.appendChild(document.createTextNode(org));
            requestElement.appendChild(orgElement);
        }

        if (locality != null) {
            Element localityElement = document.createElement("locality");
            localityElement.appendChild(document.createTextNode(locality));
            requestElement.appendChild(localityElement);
        }

        if (state != null) {
            Element stateElement = document.createElement("state");
            stateElement.appendChild(document.createTextNode(state));
            requestElement.appendChild(stateElement);
        }

        if (country != null) {
            Element countryElement = document.createElement("country");
            countryElement.appendChild(document.createTextNode(country));
            requestElement.appendChild(countryElement);
        }

        Element matchExactlyElement = document.createElement("matchExactly");
        matchExactlyElement.appendChild(document.createTextNode(Boolean.toString(matchExactly)));
        requestElement.appendChild(matchExactlyElement);

        if (status != null) {
            Element statusElement = document.createElement("status");
            statusElement.appendChild(document.createTextNode(status));
            requestElement.appendChild(statusElement);
        }

        if (revokedBy != null) {
            Element revokedByElement = document.createElement("revokedBy");
            revokedByElement.appendChild(document.createTextNode(revokedBy));
            requestElement.appendChild(revokedByElement);
        }

        if (revokedOnFrom != null) {
            Element revokedOnFromElement = document.createElement("revokedOnFrom");
            revokedOnFromElement.appendChild(document.createTextNode(revokedOnFrom));
            requestElement.appendChild(revokedOnFromElement);
        }

        if (revokedOnTo != null) {
            Element revokedOnToElement = document.createElement("revokedOnTo");
            revokedOnToElement.appendChild(document.createTextNode(revokedOnTo));
            requestElement.appendChild(revokedOnToElement);
        }

        if (revocationReason != null) {
            Element revocationReasonElement = document.createElement("revocationReason");
            revocationReasonElement.appendChild(document.createTextNode(revocationReason));
            requestElement.appendChild(revocationReasonElement);
        }

        if (issuedBy != null) {
            Element issuedByElement = document.createElement("issuedBy");
            issuedByElement.appendChild(document.createTextNode(issuedBy));
            requestElement.appendChild(issuedByElement);
        }

        if (issuedOnFrom != null) {
            Element issuedOnFromElement = document.createElement("issuedOnFrom");
            issuedOnFromElement.appendChild(document.createTextNode(issuedOnFrom));
            requestElement.appendChild(issuedOnFromElement);
        }

        if (issuedOnTo != null) {
            Element issuedOnToElement = document.createElement("issuedOnTo");
            issuedOnToElement.appendChild(document.createTextNode(issuedOnTo));
            requestElement.appendChild(issuedOnToElement);
        }

        if (validNotBeforeFrom != null) {
            Element validNotBeforeFromElement = document.createElement("validNotBeforeFrom");
            validNotBeforeFromElement.appendChild(document.createTextNode(validNotBeforeFrom));
            requestElement.appendChild(validNotBeforeFromElement);
        }

        if (validNotBeforeTo != null) {
            Element validNotBeforeToElement = document.createElement("validNotBeforeTo");
            validNotBeforeToElement.appendChild(document.createTextNode(validNotBeforeTo));
            requestElement.appendChild(validNotBeforeToElement);
        }

        if (validNotAfterFrom != null) {
            Element validNotAfterFromElement = document.createElement("validNotAfterFrom");
            validNotAfterFromElement.appendChild(document.createTextNode(validNotAfterFrom));
            requestElement.appendChild(validNotAfterFromElement);
        }

        if (validNotAfterTo != null) {
            Element validNotAfterToElement = document.createElement("validNotAfterTo");
            validNotAfterToElement.appendChild(document.createTextNode(validNotAfterTo));
            requestElement.appendChild(validNotAfterToElement);
        }

        if (validityOperation != null) {
            Element validityOperationElement = document.createElement("validityOperation");
            validityOperationElement.appendChild(document.createTextNode(validityOperation));
            requestElement.appendChild(validityOperationElement);
        }

        if (validityCount != null) {
            Element validityCountElement = document.createElement("validityCount");
            validityCountElement.appendChild(document.createTextNode(Integer.toString(validityCount)));
            requestElement.appendChild(validityCountElement);
        }

        if (validityUnit != null) {
            Element validityUnitElement = document.createElement("validityUnit");
            validityUnitElement.appendChild(document.createTextNode(Long.toString(validityUnit)));
            requestElement.appendChild(validityUnitElement);
        }

        if (certTypeSubEmailCA != null) {
            Element certTypeSubEmailCAElement = document.createElement("certTypeSubEmailCA");
            certTypeSubEmailCAElement.appendChild(document.createTextNode(certTypeSubEmailCA));
            requestElement.appendChild(certTypeSubEmailCAElement);
        }

        if (certTypeSubSSLCA != null) {
            Element certTypeSubSSLCAElement = document.createElement("certTypeSubSSLCA");
            certTypeSubSSLCAElement.appendChild(document.createTextNode(certTypeSubSSLCA));
            requestElement.appendChild(certTypeSubSSLCAElement);
        }

        if (certTypeSecureEmail != null) {
            Element certTypeSecureEmailElement = document.createElement("certTypeSecureEmail");
            certTypeSecureEmailElement.appendChild(document.createTextNode(certTypeSecureEmail));
            requestElement.appendChild(certTypeSecureEmailElement);
        }

        if (certTypeSSLClient != null) {
            Element certTypeSSLClientElement = document.createElement("certTypeSSLClient");
            certTypeSSLClientElement.appendChild(document.createTextNode(certTypeSSLClient));
            requestElement.appendChild(certTypeSSLClientElement);
        }

        if (certTypeSSLServer != null) {
            Element certTypeSSLServerElement = document.createElement("certTypeSSLServer");
            certTypeSSLServerElement.appendChild(document.createTextNode(certTypeSSLServer));
            requestElement.appendChild(certTypeSSLServerElement);
        }

        Element revokedByInUseElement = document.createElement("revokedByInUse");
        revokedByInUseElement.appendChild(document.createTextNode(Boolean.toString(revokedByInUse)));
        requestElement.appendChild(revokedByInUseElement);

        Element revokedOnInUseElement = document.createElement("revokedOnInUse");
        revokedOnInUseElement.appendChild(document.createTextNode(Boolean.toString(revokedOnInUse)));
        requestElement.appendChild(revokedOnInUseElement);

        Element revocationReasonInUseElement = document.createElement("revocationReasonInUse");
        revocationReasonInUseElement.appendChild(document.createTextNode(Boolean.toString(revocationReasonInUse)));
        requestElement.appendChild(revocationReasonInUseElement);

        Element issuedByInUseElement = document.createElement("issuedByInUse");
        issuedByInUseElement.appendChild(document.createTextNode(Boolean.toString(issuedByInUse)));
        requestElement.appendChild(issuedByInUseElement);

        Element issuedOnInUseElement = document.createElement("issuedOnInUse");
        issuedOnInUseElement.appendChild(document.createTextNode(Boolean.toString(issuedOnInUse)));
        requestElement.appendChild(issuedOnInUseElement);

        Element validNotBeforeInUseElement = document.createElement("validNotBeforeInUse");
        validNotBeforeInUseElement.appendChild(document.createTextNode(Boolean.toString(validNotBeforeInUse)));
        requestElement.appendChild(validNotBeforeInUseElement);

        Element validNotAfterInUseElement = document.createElement("validNotAfterInUse");
        validNotAfterInUseElement.appendChild(document.createTextNode(Boolean.toString(validNotAfterInUse)));
        requestElement.appendChild(validNotAfterInUseElement);

        Element validityLengthInUseElement = document.createElement("validityLengthInUse");
        validityLengthInUseElement.appendChild(document.createTextNode(Boolean.toString(validityLengthInUse)));
        requestElement.appendChild(validityLengthInUseElement);

        Element certTypeInUseElement = document.createElement("certTypeInUse");
        certTypeInUseElement.appendChild(document.createTextNode(Boolean.toString(certTypeInUse)));
        requestElement.appendChild(certTypeInUseElement);

        return requestElement;
    }

    public static CertSearchRequest fromDOM(Element requestElement) {

        CertSearchRequest request = new CertSearchRequest();

        NodeList issuerDNList = requestElement.getElementsByTagName("issuerDN");
        if (issuerDNList.getLength() > 0) {
            String value = issuerDNList.item(0).getTextContent();
            request.setIssuerDN(value);
        }

        NodeList serialNumberRangeInUseList = requestElement.getElementsByTagName("serialNumberRangeInUse");
        if (serialNumberRangeInUseList.getLength() > 0) {
            String value = serialNumberRangeInUseList.item(0).getTextContent();
            request.setSerialNumberRangeInUse(Boolean.parseBoolean(value));
        }

        NodeList serialToList = requestElement.getElementsByTagName("serialTo");
        if (serialToList.getLength() > 0) {
            String value = serialToList.item(0).getTextContent();
            request.setSerialTo(value);
        }

        NodeList serialFromList = requestElement.getElementsByTagName("serialFrom");
        if (serialFromList.getLength() > 0) {
            String value = serialFromList.item(0).getTextContent();
            request.setSerialFrom(value);
        }

        NodeList subjectInUseList = requestElement.getElementsByTagName("subjectInUse");
        if (subjectInUseList.getLength() > 0) {
            String value = subjectInUseList.item(0).getTextContent();
            request.setSubjectInUse(Boolean.parseBoolean(value));
        }

        NodeList eMailList = requestElement.getElementsByTagName("eMail");
        if (eMailList.getLength() > 0) {
            String value = eMailList.item(0).getTextContent();
            request.setEmail(value);
        }

        NodeList commonNameList = requestElement.getElementsByTagName("commonName");
        if (commonNameList.getLength() > 0) {
            String value = commonNameList.item(0).getTextContent();
            request.setCommonName(value);
        }

        NodeList userIDList = requestElement.getElementsByTagName("userID");
        if (userIDList.getLength() > 0) {
            String value = userIDList.item(0).getTextContent();
            request.setUserID(value);
        }

        NodeList orgUnitList = requestElement.getElementsByTagName("orgUnit");
        if (orgUnitList.getLength() > 0) {
            String value = orgUnitList.item(0).getTextContent();
            request.setOrgUnit(value);
        }

        NodeList orgList = requestElement.getElementsByTagName("org");
        if (orgList.getLength() > 0) {
            String value = orgList.item(0).getTextContent();
            request.setOrg(value);
        }

        NodeList localityList = requestElement.getElementsByTagName("locality");
        if (localityList.getLength() > 0) {
            String value = localityList.item(0).getTextContent();
            request.setLocality(value);
        }

        NodeList stateList = requestElement.getElementsByTagName("state");
        if (stateList.getLength() > 0) {
            String value = stateList.item(0).getTextContent();
            request.setState(value);
        }

        NodeList countryList = requestElement.getElementsByTagName("country");
        if (countryList.getLength() > 0) {
            String value = countryList.item(0).getTextContent();
            request.setCountry(value);
        }

        NodeList matchExactlyList = requestElement.getElementsByTagName("matchExactly");
        if (matchExactlyList.getLength() > 0) {
            String value = matchExactlyList.item(0).getTextContent();
            request.setMatchExactly(Boolean.parseBoolean(value));
        }

        NodeList statusList = requestElement.getElementsByTagName("status");
        if (statusList.getLength() > 0) {
            String value = statusList.item(0).getTextContent();
            request.setStatus(value);
        }

        NodeList revokedByList = requestElement.getElementsByTagName("revokedBy");
        if (revokedByList.getLength() > 0) {
            String value = revokedByList.item(0).getTextContent();
            request.setRevokedBy(value);
        }

        NodeList revokedOnFromList = requestElement.getElementsByTagName("revokedOnFrom");
        if (revokedOnFromList.getLength() > 0) {
            String value = revokedOnFromList.item(0).getTextContent();
            request.setRevokedOnFrom(value);
        }

        NodeList revokedOnToList = requestElement.getElementsByTagName("revokedOnTo");
        if (revokedOnToList.getLength() > 0) {
            String value = revokedOnToList.item(0).getTextContent();
            request.setRevokedOnTo(value);
        }

        NodeList revocationReasonList = requestElement.getElementsByTagName("revocationReason");
        if (revocationReasonList.getLength() > 0) {
            String value = revocationReasonList.item(0).getTextContent();
            request.setRevocationReason(value);
        }

        NodeList issuedByList = requestElement.getElementsByTagName("issuedBy");
        if (issuedByList.getLength() > 0) {
            String value = issuedByList.item(0).getTextContent();
            request.setIssuedBy(value);
        }

        NodeList issuedOnFromList = requestElement.getElementsByTagName("issuedOnFrom");
        if (issuedOnFromList.getLength() > 0) {
            String value = issuedOnFromList.item(0).getTextContent();
            request.setIssuedOnFrom(value);
        }

        NodeList issuedOnToList = requestElement.getElementsByTagName("issuedOnTo");
        if (issuedOnToList.getLength() > 0) {
            String value = issuedOnToList.item(0).getTextContent();
            request.setIssuedOnTo(value);
        }

        NodeList validNotBeforeFromList = requestElement.getElementsByTagName("validNotBeforeFrom");
        if (validNotBeforeFromList.getLength() > 0) {
            String value = validNotBeforeFromList.item(0).getTextContent();
            request.setValidNotBeforeFrom(value);
        }

        NodeList validNotBeforeToList = requestElement.getElementsByTagName("validNotBeforeTo");
        if (validNotBeforeToList.getLength() > 0) {
            String value = validNotBeforeToList.item(0).getTextContent();
            request.setValidNotBeforeTo(value);
        }

        NodeList validNotAfterFromList = requestElement.getElementsByTagName("validNotAfterFrom");
        if (validNotAfterFromList.getLength() > 0) {
            String value = validNotAfterFromList.item(0).getTextContent();
            request.setValidNotAfterFrom(value);
        }

        NodeList validNotAfterToList = requestElement.getElementsByTagName("validNotAfterTo");
        if (validNotAfterToList.getLength() > 0) {
            String value = validNotAfterToList.item(0).getTextContent();
            request.setValidNotAfterTo(value);
        }

        NodeList validityOperationList = requestElement.getElementsByTagName("validityOperation");
        if (validityOperationList.getLength() > 0) {
            String value = validityOperationList.item(0).getTextContent();
            request.setValidityOperation(value);
        }

        NodeList validityCountList = requestElement.getElementsByTagName("validityCount");
        if (validityCountList.getLength() > 0) {
            String value = validityCountList.item(0).getTextContent();
            request.setValidityCount(Integer.valueOf(value));
        }

        NodeList validityUnitList = requestElement.getElementsByTagName("validityUnit");
        if (validityUnitList.getLength() > 0) {
            String value = validityUnitList.item(0).getTextContent();
            request.setValidityUnit(Long.valueOf(value));
        }

        NodeList certTypeSubEmailCAList = requestElement.getElementsByTagName("certTypeSubEmailCA");
        if (certTypeSubEmailCAList.getLength() > 0) {
            String value = certTypeSubEmailCAList.item(0).getTextContent();
            request.setCertTypeSubEmailCA(value);
        }

        NodeList certTypeSubSSLCAList = requestElement.getElementsByTagName("certTypeSubSSLCA");
        if (certTypeSubSSLCAList.getLength() > 0) {
            String value = certTypeSubSSLCAList.item(0).getTextContent();
            request.setCertTypeSubSSLCA(value);
        }

        NodeList certTypeSecureEmailList = requestElement.getElementsByTagName("certTypeSecureEmail");
        if (certTypeSecureEmailList.getLength() > 0) {
            String value = certTypeSecureEmailList.item(0).getTextContent();
            request.setCertTypeSecureEmail(value);
        }

        NodeList certTypeSSLClientList = requestElement.getElementsByTagName("certTypeSSLClient");
        if (certTypeSSLClientList.getLength() > 0) {
            String value = certTypeSSLClientList.item(0).getTextContent();
            request.setCertTypeSSLClient(value);
        }

        NodeList certTypeSSLServerList = requestElement.getElementsByTagName("certTypeSSLServer");
        if (certTypeSSLServerList.getLength() > 0) {
            String value = certTypeSSLServerList.item(0).getTextContent();
            request.setCertTypeSSLServer(value);
        }

        NodeList revokedByInUseList = requestElement.getElementsByTagName("revokedByInUse");
        if (revokedByInUseList.getLength() > 0) {
            String value = revokedByInUseList.item(0).getTextContent();
            request.setRevokedByInUse(Boolean.parseBoolean(value));
        }

        NodeList revokedOnInUseList = requestElement.getElementsByTagName("revokedOnInUse");
        if (revokedOnInUseList.getLength() > 0) {
            String value = revokedOnInUseList.item(0).getTextContent();
            request.setRevokedOnInUse(Boolean.parseBoolean(value));
        }

        NodeList revocationReasonInUseList = requestElement.getElementsByTagName("revocationReasonInUse");
        if (revocationReasonInUseList.getLength() > 0) {
            String value = revocationReasonInUseList.item(0).getTextContent();
            request.setRevocationReasonInUse(Boolean.parseBoolean(value));
        }

        NodeList issuedByInUseList = requestElement.getElementsByTagName("issuedByInUse");
        if (issuedByInUseList.getLength() > 0) {
            String value = issuedByInUseList.item(0).getTextContent();
            request.setIssuedByInUse(Boolean.parseBoolean(value));
        }

        NodeList issuedOnInUseList = requestElement.getElementsByTagName("issuedOnInUse");
        if (issuedOnInUseList.getLength() > 0) {
            String value = issuedOnInUseList.item(0).getTextContent();
            request.setIssuedOnInUse(Boolean.parseBoolean(value));
        }

        NodeList validNotBeforeInUseList = requestElement.getElementsByTagName("validNotBeforeInUse");
        if (validNotBeforeInUseList.getLength() > 0) {
            String value = validNotBeforeInUseList.item(0).getTextContent();
            request.setValidNotBeforeInUse(Boolean.parseBoolean(value));
        }

        NodeList validNotAfterInUseList = requestElement.getElementsByTagName("validNotAfterInUse");
        if (validNotAfterInUseList.getLength() > 0) {
            String value = validNotAfterInUseList.item(0).getTextContent();
            request.setValidNotAfterInUse(Boolean.parseBoolean(value));
        }

        NodeList validityLengthInUseList = requestElement.getElementsByTagName("validityLengthInUse");
        if (validityLengthInUseList.getLength() > 0) {
            String value = validityLengthInUseList.item(0).getTextContent();
            request.setValidityLengthInUse(Boolean.parseBoolean(value));
        }

        NodeList certTypeInUseList = requestElement.getElementsByTagName("certTypeInUse");
        if (certTypeInUseList.getLength() > 0) {
            String value = certTypeInUseList.item(0).getTextContent();
            request.setCertTypeInUse(Boolean.parseBoolean(value));
        }

        return request;
    }

    public String toXML() throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.newDocument();

        Element rootElement = toDOM(document);
        document.appendChild(rootElement);

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        DOMSource domSource = new DOMSource(document);
        StringWriter sw = new StringWriter();
        StreamResult streamResult = new StreamResult(sw);
        transformer.transform(domSource, streamResult);

        return sw.toString();
    }

    public static CertSearchRequest fromXML(String xml) throws Exception {

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new InputSource(new StringReader(xml)));

        Element rootElement = document.getDocumentElement();
        return fromDOM(rootElement);
    }

    public static CertSearchRequest fromMap(Map<String, String[]> elements) {

        CertSearchRequest request = new CertSearchRequest();

        elements.forEach((key, values) -> {
            switch (key) {
            case "issuerDN":
                request.setIssuerDN(values[0]);
                break;
            case "serialNumberRangeInUse":
                request.setSerialNumberRangeInUse(Boolean.parseBoolean(values[0]));
                break;
            case "serialTo":
                request.setSerialTo(values[0]);
                break;
            case "serialFrom":
                request.setSerialFrom(values[0]);
                break;
            case "subjectInUse":
                request.setSubjectInUse(Boolean.parseBoolean(values[0]));
                break;
            case "eMail":
                request.setEmail(values[0]);
                break;
            case "commonName":
                request.setCommonName(values[0]);
                break;
            case "userID":
                request.setUserID(values[0]);
                break;
            case "orgUnit":
                request.setOrgUnit(values[0]);
                break;
            case "org":
                request.setOrg(values[0]);
                break;
            case "locality":
                request.setLocality(values[0]);
                break;
            case "state":
                request.setState(values[0]);
                break;
            case "country":
                request.setCountry(values[0]);
                break;
            case "matchExactly":
                request.setMatchExactly(Boolean.parseBoolean(values[0]));
                break;
            case "status":
                request.setStatus(values[0]);
                break;
            case "revokedBy":
                request.setRevokedBy(values[0]);
                break;
            case "revokedOnFrom":
                request.setRevokedOnFrom(values[0]);
                break;
            case "revokedOnTo":
                request.setRevokedOnTo(values[0]);
                break;
            case "revocationReason":
                request.setRevocationReason(values[0]);
                break;
            case "issuedBy":
                request.setIssuedBy(values[0]);
                break;
            case "issuedOnFrom":
                request.setIssuedOnFrom(values[0]);
                break;
            case "issuedOnTo":
                request.setIssuedOnTo(values[0]);
                break;
            case "validNotBeforeFrom":
                request.setValidNotBeforeFrom(values[0]);
                break;
            case "validNotBeforeTo":
                request.setValidNotBeforeTo(values[0]);
                break;
            case "validNotAfterFrom":
                request.setValidNotAfterFrom(values[0]);
                break;
            case "validNotAfterTo":
                request.setValidNotAfterTo(values[0]);
                break;
            case "validityOperation":
                request.setValidityOperation(values[0]);
                break;
            case "validityCount":
                request.setValidityCount(Integer.valueOf(values[0]));
                break;
            case "validityUnit":
                request.setValidityUnit(Long.valueOf(values[0]));
                break;
            case "certTypeSubEmailCA":
                request.setCertTypeSubEmailCA(values[0]);
                break;
            case "certTypeSubSSLCA":
                request.setCertTypeSubSSLCA(values[0]);
                break;
            case "certTypeSecureEmail":
                request.setCertTypeSecureEmail(values[0]);
                break;
            case "certTypeSSLClient":
                request.setCertTypeSSLClient(values[0]);
                break;
            case "certTypeSSLServer":
                request.setCertTypeSSLServer(values[0]);
                break;
            case "revokedByInUse":
                request.setRevokedByInUse(Boolean.parseBoolean(values[0]));
                break;
            case "revokedOnInUse":
                request.setRevokedOnInUse(Boolean.parseBoolean(values[0]));
                break;
            case "revocationReasonInUse":
                request.setRevocationReasonInUse(Boolean.parseBoolean(values[0]));
                break;
            case "issuedByInUse":
                request.setIssuedByInUse(Boolean.parseBoolean(values[0]));
                break;
            case "issuedOnInUse":
                request.setIssuedOnInUse(Boolean.parseBoolean(values[0]));
                break;
            case "validNotBeforeInUse":
                request.setValidNotBeforeInUse(Boolean.parseBoolean(values[0]));
                break;
            case "validNotAfterInUse":
                request.setValidNotAfterInUse(Boolean.parseBoolean(values[0]));
                break;
            case "validityLengthInUse":
                request.setValidityLengthInUse(Boolean.parseBoolean(values[0]));
                break;
            case "certTypeInUse":
                request.setCertTypeInUse(Boolean.parseBoolean(values[0]));
                break;
            default:
            }
        });

        return request;
    }

}
