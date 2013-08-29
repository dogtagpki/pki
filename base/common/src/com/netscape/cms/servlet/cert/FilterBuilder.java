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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.cert;

import java.util.Calendar;
import java.util.StringTokenizer;

import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author jmagne
 *
 */
public class FilterBuilder {
    private final static String MATCH_EXACTLY = "exact";
    private String searchFilter = null;
    private CertSearchRequest request = null;

    public FilterBuilder(CertSearchRequest request) {
        this.request = request;
    }

    public String buildFilter() {
        StringBuffer filter = new StringBuffer();
        buildSerialNumberRangeFilter(filter);
        buildSubjectFilter(filter);
        buildStatusFilter(filter);
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

        if (!request.getSerialNumberRangeInUse()) {
            return;
        }
        boolean changed = false;
        String serialFrom = request.getSerialFrom();
        if (serialFrom != null && !serialFrom.equals("")) {
            filter.append("(certRecordId>=" + LDAPUtil.escapeFilter(serialFrom) + ")");
            changed = true;
        }
        String serialTo = request.getSerialTo();
        if (serialTo != null && !serialTo.equals("")) {
            filter.append("(certRecordId<=" + LDAPUtil.escapeFilter(serialTo) + ")");
            changed = true;
        }
        if (!changed) {
            filter.append("(certRecordId=*)");
        }

    }

    private void buildSubjectFilter(StringBuffer filter) {
        if (!request.getSubjectInUse()) {
            return;
        }
        StringBuffer lf = new StringBuffer();

        String matchStr = null;
        boolean match = request.getMatchExactly();

        if (match == true) {
            matchStr = MATCH_EXACTLY;
        }

        buildAVAFilter(request.getEmail(), "E", lf, matchStr);
        buildAVAFilter(request.getCommonName(), "CN", lf, matchStr);
        buildAVAFilter(request.getUserID(), "UID", lf, matchStr);
        buildAVAFilter(request.getOrgUnit(), "OU", lf, matchStr);
        buildAVAFilter(request.getOrg(), "O", lf, matchStr);
        buildAVAFilter(request.getLocality(), "L", lf, matchStr);
        buildAVAFilter(request.getState(), "ST", lf, matchStr);
        buildAVAFilter(request.getCountry(), "C", lf, matchStr);

        if (lf.length() == 0) {
            filter.append("("+ICertRecord.ATTR_X509CERT_SUBJECT+"=*)");
            return;
        }
        if (matchStr != null && matchStr.equals(MATCH_EXACTLY)) {
            filter.append("(&");
            filter.append(lf);
            filter.append(")");
        } else {
            filter.append("(|");
            filter.append(lf);
            filter.append(")");
        }
    }

    private void buildStatusFilter(StringBuffer filter) {
        String status = request.getStatus();
        if (status == null || status.equals("")) {
            return;
        }
        filter.append("(certStatus=");
        filter.append(LDAPUtil.escapeFilter(status));
        filter.append(")");
    }

    private void buildRevokedByFilter(StringBuffer filter) {
        if (!request.getRevokedByInUse()) {
            return;
        }

        String revokedBy = request.getRevokedBy();
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
        if (prefix == null || prefix.length() == 0) return;
        long epoch = Long.parseLong(prefix);
        Calendar from = Calendar.getInstance();
        from.setTimeInMillis(epoch);
        filter.append("(");
        filter.append(LDAPUtil.escapeFilter(outStr));
        filter.append(Long.toString(from.getTimeInMillis() + adjustment));
        filter.append(")");
    }

    private void buildRevokedOnFilter(StringBuffer filter) {
        if (!request.getRevokedOnInUse()) {
            return;
        }
        buildDateFilter(request.getRevokedOnFrom(), "certRevokedOn>=", 0, filter);
        buildDateFilter(request.getRevokedOnTo(), "certRevokedOn<=", 86399999, filter);
    }

    private void buildRevocationReasonFilter(StringBuffer filter) {
        if (!request.getRevocationReasonInUse()) {
            return;
        }
        String reasons = request.getRevocationReason();
        if (reasons == null) {
            return;
        }
        String queryCertFilter = null;
        StringTokenizer st = new StringTokenizer(reasons, ",");
        int count = st.countTokens();
        if (st.hasMoreTokens()) {
            if (count >=2) filter.append("(|");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                if (queryCertFilter == null) {
                    queryCertFilter = "";
                }
                filter.append("(x509cert.certRevoInfo=");
                filter.append(LDAPUtil.escapeFilter(token));
                filter.append(")");
            }
            if (count >= 2) filter.append(")");
        }
    }

    private void buildIssuedByFilter(StringBuffer filter) {
        if (!request.getIssuedByInUse()) {
            return;
        }
        String issuedBy = request.getIssuedBy();
        if (issuedBy == null || issuedBy.equals("")) {
            filter.append("(certIssuedBy=*)");
        } else {
            filter.append("(certIssuedBy=");
            filter.append(LDAPUtil.escapeFilter(issuedBy));
            filter.append(")");
        }
    }

    private void buildIssuedOnFilter(StringBuffer filter) {
        if (!request.getIssuedOnInUse()) {
            return;
        }
        buildDateFilter(request.getIssuedOnFrom(), "certCreateTime>=", 0, filter);
        buildDateFilter(request.getIssuedOnTo(), "certCreateTime<=", 86399999, filter);
    }

    private void buildValidNotBeforeFilter(StringBuffer filter) {
        if (!request.getValidNotBeforeInUse()) {
            return;
        }
        buildDateFilter(request.getValidNotBeforeFrom(), ICertRecord.ATTR_X509CERT_NOT_BEFORE+">=", 0, filter);
        buildDateFilter(request.getValidNotBeforeTo(), ICertRecord.ATTR_X509CERT_NOT_BEFORE+"<=", 86399999, filter);

    }

    private void buildValidNotAfterFilter(StringBuffer filter) {
        if (!request.getValidNotAfterInUse()) {
            return;
        }
        buildDateFilter(request.getValidNotAfterFrom(), ICertRecord.ATTR_X509CERT_NOT_AFTER+">=", 0, filter);
        buildDateFilter(request.getValidNotAfterTo(), ICertRecord.ATTR_X509CERT_NOT_AFTER+"<=", 86399999, filter);

    }

    private void buildValidityLengthFilter(StringBuffer filter) {
        if (!request.getValidityLengthInUse()) {
            return;
        }

        String op = request.getValidityOperation();
        Integer count = request.getValidityCount();
        Long unit = request.getValidityUnit();

        filter.append("(");
        filter.append(ICertRecord.ATTR_X509CERT_DURATION);
        filter.append(LDAPUtil.escapeFilter(op));
        filter.append(count * unit);
        filter.append(")");
    }

    private void buildCertTypeFilter(StringBuffer filter) {
        if (!request.getCertTypeInUse()) {
            return;
        }
        if (isOn(request.getCertTypeSSLClient())) {
            filter.append("(x509cert.nsExtension.SSLClient=on)");
        } else if (isOff(request.getCertTypeSSLClient())) {
            filter.append("(x509cert.nsExtension.SSLClient=off)");
        }
        if (isOn(request.getCertTypeSSLServer())) {
            filter.append("(x509cert.nsExtension.SSLServer=on)");
        } else if (isOff(request.getCertTypeSSLServer())) {
            filter.append("(x509cert.nsExtension.SSLServer=off)");
        }
        if (isOn(request.getCertTypeSecureEmail())) {
            filter.append("(x509cert.nsExtension.SecureEmail=on)");
        } else if (isOff(request.getCertTypeSecureEmail())) {
            filter.append("(x509cert.nsExtension.SecureEmail=off)");
        }
        if (isOn(request.getCertTypeSubSSLCA())) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=on)");
        } else if (isOff(request.getCertTypeSubSSLCA())) {
            filter.append("(x509cert.nsExtension.SubordinateSSLCA=off)");
        }
        if (isOn(request.getCertTypeSubEmailCA())) {
            filter.append("(x509cert.nsExtension.SubordinateEmailCA=on)");
        } else if (isOff(request.getCertTypeSubEmailCA())) {
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
                lf.append("("+ICertRecord.ATTR_X509CERT_SUBJECT+"=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(param)));
                lf.append(",*)");
                lf.append("("+ICertRecord.ATTR_X509CERT_SUBJECT+"=*");
                lf.append(avaName);
                lf.append("=");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(param)));
                lf.append(")");
                lf.append(")");
            } else {
                lf.append("("+ICertRecord.ATTR_X509CERT_SUBJECT+"=*");
                lf.append(avaName);
                lf.append("=");
                lf.append("*");
                lf.append(LDAPUtil.escapeFilter(LDAPUtil.escapeRDNValue(param)));
                lf.append("*)");
            }
        }

    }
}
