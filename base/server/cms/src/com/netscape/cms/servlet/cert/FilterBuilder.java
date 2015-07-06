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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.StringTokenizer;

import com.netscape.certsrv.cert.CertSearchRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author jmagne
 *
 */
public class FilterBuilder {

    private List<String> filters = new ArrayList<String>();
    private CertSearchRequest request;

    public FilterBuilder(CertSearchRequest request) {
        this.request = request;
    }

    public String buildFilter() {

        buildSerialNumberRangeFilter();
        buildSubjectFilter();
        buildStatusFilter();
        buildRevokedByFilter();
        buildRevokedOnFilter();
        buildRevocationReasonFilter();
        buildIssuedByFilter();
        buildIssuedOnFilter();
        buildValidNotBeforeFilter();
        buildValidNotAfterFilter();
        buildValidityLengthFilter();
        buildCertTypeFilter();

        if (filters.size() == 0) {
            return "(certstatus=*)"; // allCerts VLV

        } else if (filters.size() == 1) {
            return filters.get(0);

        } else {
            StringBuilder sb = new StringBuilder();
            for (String filter : filters) {
                sb.append(filter);
            }
            return "(&" + sb + ")";
        }
    }

    private void buildSerialNumberRangeFilter() {

        String serialFrom = request.getSerialFrom();
        if (serialFrom != null && !serialFrom.equals("")) {
            filters.add("(certRecordId>=" + LDAPUtil.escapeFilter(serialFrom) + ")");
        }

        String serialTo = request.getSerialTo();
        if (serialTo != null && !serialTo.equals("")) {
            filters.add("(certRecordId<=" + LDAPUtil.escapeFilter(serialTo) + ")");
        }
    }

    private void buildSubjectFilter() {

        if (!request.getSubjectInUse()) {
            return;
        }

        StringBuffer lf = new StringBuffer();
        boolean match = request.getMatchExactly();

        buildAVAFilter(request.getEmail(), "E", lf, match);
        buildAVAFilter(request.getCommonName(), "CN", lf, match);
        buildAVAFilter(request.getUserID(), "UID", lf, match);
        buildAVAFilter(request.getOrgUnit(), "OU", lf, match);
        buildAVAFilter(request.getOrg(), "O", lf, match);
        buildAVAFilter(request.getLocality(), "L", lf, match);
        buildAVAFilter(request.getState(), "ST", lf, match);
        buildAVAFilter(request.getCountry(), "C", lf, match);

        if (lf.length() == 0) {
            filters.add("(" + ICertRecord.ATTR_X509CERT_SUBJECT + "=*)");

        } else if (match) {
            filters.add("(&" + lf + ")");

        } else {
            filters.add("(|" + lf + ")");
        }
    }

    private void buildStatusFilter() {

        String status = request.getStatus();
        if (status == null || status.equals("")) {
            return;
        }

        filters.add("(certStatus=" + LDAPUtil.escapeFilter(status) + ")");
    }

    private void buildRevokedByFilter() {

        if (!request.getRevokedByInUse()) {
            return;
        }

        String revokedBy = request.getRevokedBy();
        if (revokedBy == null || revokedBy.equals("")) {
            filters.add("(certRevokedBy=*)");

        } else {
            filters.add("(certRevokedBy=" + LDAPUtil.escapeFilter(revokedBy) + ")");
        }
    }

    private void buildDateFilter(String prefix,
            String outStr, long adjustment) {

        if (prefix == null || prefix.length() == 0) return;

        long epoch = Long.parseLong(prefix);
        Calendar from = Calendar.getInstance();
        from.setTimeInMillis(epoch);

        StringBuilder filter = new StringBuilder();
        filter.append("(");
        filter.append(LDAPUtil.escapeFilter(outStr));
        filter.append(Long.toString(from.getTimeInMillis() + adjustment));
        filter.append(")");

        filters.add(filter.toString());
    }

    private void buildRevokedOnFilter() {

        if (!request.getRevokedOnInUse()) {
            return;
        }

        buildDateFilter(request.getRevokedOnFrom(), "certRevokedOn>=", 0);
        buildDateFilter(request.getRevokedOnTo(), "certRevokedOn<=", 86399999);
    }

    private void buildRevocationReasonFilter() {

        if (!request.getRevocationReasonInUse()) {
            return;
        }

        String reasons = request.getRevocationReason();
        if (reasons == null) {
            return;
        }

        StringBuilder filter = new StringBuilder();
        StringTokenizer st = new StringTokenizer(reasons, ",");
        int count = st.countTokens();
        if (st.hasMoreTokens()) {
            if (count >= 2) filter.append("(|");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                filter.append("(x509cert.certRevoInfo=");
                filter.append(LDAPUtil.escapeFilter(token));
                filter.append(")");
            }
            if (count >= 2) filter.append(")");
        }

        filters.add(filter.toString());
    }

    private void buildIssuedByFilter() {

        if (!request.getIssuedByInUse()) {
            return;
        }

        String issuedBy = request.getIssuedBy();
        if (issuedBy == null || issuedBy.equals("")) {
            filters.add("(certIssuedBy=*)");
        } else {
            filters.add("(certIssuedBy=" + LDAPUtil.escapeFilter(issuedBy) + ")");
        }
    }

    private void buildIssuedOnFilter() {

        if (!request.getIssuedOnInUse()) {
            return;
        }

        buildDateFilter(request.getIssuedOnFrom(), "certCreateTime>=", 0);
        buildDateFilter(request.getIssuedOnTo(), "certCreateTime<=", 86399999);
    }

    private void buildValidNotBeforeFilter() {

        if (!request.getValidNotBeforeInUse()) {
            return;
        }

        buildDateFilter(request.getValidNotBeforeFrom(), ICertRecord.ATTR_X509CERT_NOT_BEFORE+">=", 0);
        buildDateFilter(request.getValidNotBeforeTo(), ICertRecord.ATTR_X509CERT_NOT_BEFORE+"<=", 86399999);

    }

    private void buildValidNotAfterFilter() {

        if (!request.getValidNotAfterInUse()) {
            return;
        }

        buildDateFilter(request.getValidNotAfterFrom(), ICertRecord.ATTR_X509CERT_NOT_AFTER+">=", 0);
        buildDateFilter(request.getValidNotAfterTo(), ICertRecord.ATTR_X509CERT_NOT_AFTER+"<=", 86399999);

    }

    private void buildValidityLengthFilter() {
        if (!request.getValidityLengthInUse()) {
            return;
        }

        String op = request.getValidityOperation();
        Integer count = request.getValidityCount();
        Long unit = request.getValidityUnit();

        StringBuilder filter = new StringBuilder();
        filter.append("(");
        filter.append(ICertRecord.ATTR_X509CERT_DURATION);
        filter.append(LDAPUtil.escapeFilter(op));
        filter.append(count * unit);
        filter.append(")");

        filters.add(filter.toString());
    }

    private void buildCertTypeFilter() {

        if (!request.getCertTypeInUse()) {
            return;
        }

        if (isOn(request.getCertTypeSSLClient())) {
            filters.add("(x509cert.nsExtension.SSLClient=on)");
        } else if (isOff(request.getCertTypeSSLClient())) {
            filters.add("(x509cert.nsExtension.SSLClient=off)");
        }

        if (isOn(request.getCertTypeSSLServer())) {
            filters.add("(x509cert.nsExtension.SSLServer=on)");
        } else if (isOff(request.getCertTypeSSLServer())) {
            filters.add("(x509cert.nsExtension.SSLServer=off)");
        }

        if (isOn(request.getCertTypeSecureEmail())) {
            filters.add("(x509cert.nsExtension.SecureEmail=on)");
        } else if (isOff(request.getCertTypeSecureEmail())) {
            filters.add("(x509cert.nsExtension.SecureEmail=off)");
        }

        if (isOn(request.getCertTypeSubSSLCA())) {
            filters.add("(x509cert.nsExtension.SubordinateSSLCA=on)");
        } else if (isOff(request.getCertTypeSubSSLCA())) {
            filters.add("(x509cert.nsExtension.SubordinateSSLCA=off)");
        }

        if (isOn(request.getCertTypeSubEmailCA())) {
            filters.add("(x509cert.nsExtension.SubordinateEmailCA=on)");
        } else if (isOff(request.getCertTypeSubEmailCA())) {
            filters.add("(x509cert.nsExtension.SubordinateEmailCA=off)");
        }
    }

    private boolean isOn(String value) {
        if (value != null && value.equals("on")) {
            return true;
        }
        return false;
    }

    private boolean isOff(String value) {
        if (value != null && value.equals("off")) {
            return true;
        }
        return false;
    }

    private void buildAVAFilter(String param,
            String avaName, StringBuffer lf, boolean match) {

        if (param != null && !param.equals("")) {
            if (match) {
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
