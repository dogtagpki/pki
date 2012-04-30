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
package com.netscape.cms.servlet.cert.model;

import java.util.Calendar;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author jmagne
 *
 */
@XmlRootElement(name = "CertSearchData")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertSearchData {

    private final static String MATCH_EXACTLY = "exact";
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
    protected String validityCount;

    @XmlElement
    protected String validityUnit;

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
        return getIssuedOnTo();
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

    public String getValidityUnit() {
        return validityUnit;
    }

    public void setValidityUnit(String validityUnit) {
        this.validityUnit = validityUnit;
    }

    public String getValidityCount() {
        return validityCount;
    }

    public void setValidityCount(String validityCount) {
        this.validityCount = validityCount;
    }

    //Cert Type

    String getCertTypeSubEmailCA() {
        return certTypeSubEmailCA;
    }

    void setCertTypeSubEmailCA(String certTypeSubEmailCA) {
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

    public CertSearchData() {
        // required for JAXB (defaults)
    }

    public void buildFromServletRequest(HttpServletRequest req) {
        //Set values from the servlet request
        if (req == null) {
            return;
        }
    }

    public CertSearchData(MultivaluedMap<String, String> form) {
    }

    public String buildFilter() {
        StringBuffer filter = new StringBuffer();
        buildSerialNumberRangeFilter(filter);
        buildSubjectFilter(filter);
        buildRevokedByFilter(filter);
        buildRevokedOnFilter(filter);
        buildRevocationReasonFilter(filter);
        buildIssuedByFilter(filter);
        buildIssuedOnFilter(filter);
        buildValidNotBeforeFilter(filter);
        buildValidNotAfterFilter(filter);
        buildValidityLengthFilter(filter);
        buildCertTypeFilter(filter);

        searchFilter = filter.toString();

        if (searchFilter != null && !searchFilter.equals("")) {
            searchFilter = "(&" + searchFilter + ")";
        }

        return searchFilter;
    }

    private void buildSerialNumberRangeFilter(StringBuffer filter) {

        if (!getSerialNumberRangeInUse()) {
            return;
        }
        boolean changed = false;
        String serialFrom = getSerialFrom();
        if (serialFrom != null && !serialFrom.equals("")) {
            filter.append("(certRecordId>=" + LDAPUtil.escapeFilter(serialFrom) + ")");
            changed = true;
        }
        String serialTo = getSerialTo();
        if (serialTo != null && !serialTo.equals("")) {
            filter.append("(certRecordId<=" + LDAPUtil.escapeFilter(serialTo) + ")");
            changed = true;
        }
        if (!changed) {
            filter.append("(certRecordId=*)");
        }

    }

    private void buildSubjectFilter(StringBuffer filter) {
        if (!getSubjectInUse()) {
            return;
        }
        StringBuffer lf = new StringBuffer();

        String matchStr = null;
        boolean match = getMatchExactly();

        if (match == true) {
            matchStr = MATCH_EXACTLY;
        }

        buildAVAFilter(getEmail(), "E", lf, matchStr);
        buildAVAFilter(getCommonName(), "CN", lf, matchStr);
        buildAVAFilter(getUserID(), "UID", lf, matchStr);
        buildAVAFilter(getOrgUnit(), "OU", lf, matchStr);
        buildAVAFilter(getOrg(), "O", lf, matchStr);
        buildAVAFilter(getLocality(), "L", lf, matchStr);
        buildAVAFilter(getState(), "ST", lf, matchStr);
        buildAVAFilter(getCountry(), "C", lf, matchStr);

        if (lf.length() == 0) {
            filter.append("(x509cert.subject=*)");
            return;
        }
        if (matchStr.equals(MATCH_EXACTLY)) {
            filter.append("(&");
            filter.append(lf);
            filter.append(")");
        } else {
            filter.append("(|");
            filter.append(lf);
            filter.append(")");
        }
    }

    private void buildRevokedByFilter(StringBuffer filter) {
        if (!getRevokedByInUse()) {
            return;
        }

        String revokedBy = getRevokedBy();
        if (revokedBy == null || revokedBy.equals("")) {
            filter.append("(certRevokedBy=*)");
        } else {
            filter.append("(certRevokedBy=");
            filter.append(LDAPUtil.escapeFilter(revokedBy));
            filter.append(")");
        }
    }

    private void buildDateFilter(String prefix,
            String outStr, long adjustment,
            StringBuffer filter) {
        long epoch = 0;
        try {
            epoch = Long.parseLong(prefix);
        } catch (NumberFormatException e) {
            // exception safely ignored
        }
        Calendar from = Calendar.getInstance();
        from.setTimeInMillis(epoch);
        filter.append("(");
        filter.append(LDAPUtil.escapeFilter(outStr));
        filter.append(Long.toString(from.getTimeInMillis() + adjustment));
        filter.append(")");
    }

    private void buildRevokedOnFilter(StringBuffer filter) {
        if (!getRevokedOnInUse()) {
            return;
        }
        buildDateFilter(getRevokedOnFrom(), "certRevokedOn>=", 0, filter);
        buildDateFilter(getRevokedOnTo(), "certRevokedOn<=", 86399999, filter);
    }

    private void buildRevocationReasonFilter(StringBuffer filter) {
        if (!getRevocationReasonInUse()) {
            return;
        }
        String reasons = getRevocationReason();
        if (reasons == null) {
            return;
        }
        String queryCertFilter = null;
        StringTokenizer st = new StringTokenizer(reasons, ",");
        if (st.hasMoreTokens()) {
            filter.append("(|");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (queryCertFilter == null) {
                    queryCertFilter = "";
                }
                filter.append("(x509cert.certRevoInfo=");
                filter.append(LDAPUtil.escapeFilter(token));
                filter.append(")");
            }
            filter.append(")");
        }
    }

    private void buildIssuedByFilter(StringBuffer filter) {
        if (!getIssuedByInUse()) {
            return;
        }
        String issuedBy = getIssuedBy();
        ;
        if (issuedBy == null || issuedBy.equals("")) {
            filter.append("(certIssuedBy=*)");
        } else {
            filter.append("(certIssuedBy=");
            filter.append(LDAPUtil.escapeFilter(issuedBy));
            filter.append(")");
        }
    }

    private void buildIssuedOnFilter(StringBuffer filter) {
        if (!getIssuedOnInUse()) {
            return;
        }
        buildDateFilter(getIssuedOnFrom(), "certCreateTime>=", 0, filter);
        buildDateFilter(getIssuedOnTo(), "certCreateTime<=", 86399999, filter);
    }

    private void buildValidNotBeforeFilter(StringBuffer filter) {
        if (!getValidNotBeforeInUse()) {
            return;
        }
        buildDateFilter(validNotBeforeFrom, "x509cert.notBefore>=", 0, filter);
        buildDateFilter(validNotBeforeTo, "x509cert.notBefore<=", 86399999, filter);

    }

    private void buildValidNotAfterFilter(StringBuffer filter) {
        if (!getValidNotAfterInUse()) {
            return;
        }
        buildDateFilter(getValidNotAfterFrom(), "x509cert.notAfter>=", 0, filter);
        buildDateFilter(getValidNotAfterTo(), "x509cert.notAfter<=", 86399999, filter);

    }

    private void buildValidityLengthFilter(StringBuffer filter) {
        if (!getValidityLengthInUse()) {
            return;
        }
        String op = getValidityOperation();
        long count = 0;
        try {
            count = Long.parseLong(getValidityCount());
        } catch (NumberFormatException e) {
            // safely ignore
        }
        long unit = 0;
        try {
            unit = Long.parseLong(getValidityUnit());
        } catch (NumberFormatException e) {
            // safely ignore
        }
        filter.append("(");
        filter.append("x509cert.duration");
        filter.append(LDAPUtil.escapeFilter(op));
        filter.append(count * unit);
        filter.append(")");
    }

    private void buildCertTypeFilter(StringBuffer filter) {
        if (!getCertTypeInUse()) {
            return;
        }
        if (isOn(getCertTypeSSLClient())) {
            filter.append("(x509cert.nsExtension.SSLClient=on)");
        } else if (isOff(getCertTypeSSLClient())) {
            filter.append("(x509cert.nsExtension.SSLClient=off)");
        }
        if (isOn(getCertTypeSSLServer())) {
            filter.append("(x509cert.nsExtension.SSLServer=on)");
        } else if (isOff(getCertTypeSSLServer())) {
            filter.append("(x509cert.nsExtension.SSLServer=off)");
        }
        if (isOn(getCertTypeSecureEmail())) {
            filter.append("(x509cert.nsExtension.SecureEmail=on)");
        } else if (isOff(getCertTypeSecureEmail())) {
            filter.append("(x509cert.nsExtension.SecureEmail=off)");
        }
        if (isOn(getCertTypeSubSSLCA())) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=on)");
        } else if (isOff(getCertTypeSubSSLCA())) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=off)");
        }
        if (isOn(getCertTypeSubEmailCA())) {
            filter.append("(x509cert.nsExtension.SubordinateEmailCA=on)");
        } else if (isOff(getCertTypeSubEmailCA())) {
            filter.append("(x509cert.nsExtension.SubordinateEmailCA=off)");
        }
    }

    private boolean isOn(String value) {
        String inUse = value;
        if (inUse == null) {
            return false;
        }
        if (inUse.equals("on")) {
            return true;
        }
        return false;
    }

    private boolean isOff(String value) {
        String inUse = value;
        if (inUse == null) {
            return false;
        }
        if (inUse.equals("off")) {
            return true;
        }
        return false;
    }

    private void buildAVAFilter(String param,
            String avaName, StringBuffer lf, String match) {
        if (param != null && !param.equals("")) {
            if (match != null && match.equals(MATCH_EXACTLY)) {
                lf.append("(|");
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeDN(param, false)));
                lf.append(",*)");
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeDN(param, false)));
                lf.append(")");
                lf.append(")");
            } else {
                lf.append("(x509cert.subject=*");
                lf.append(avaName);
                lf.append("=");
                lf.append("*");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeDN(param, false)));
                lf.append("*)");
            }
        }

    }

    private String searchFilter = null;

    public String getSearchFilter() {
        return searchFilter;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }
}
