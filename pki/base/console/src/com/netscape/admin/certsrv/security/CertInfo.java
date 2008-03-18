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
package com.netscape.admin.certsrv.security;


class CertInfo {

    String _certName;
    String _issuer;
    String _subject;
    String _serialNumber;
    String _version;
    String _validFrom;
    String _validTo;
    String _fingerPrint;
    boolean _trustCert;
    boolean _certDeleted;
    String _certTitle;


    public CertInfo(String certName, String issuer, String subject,
            String serialNumber, String version, String validFrom,
            String validTo, String fingerPrint, String trustCert,
            String certDeleted, String certTitle) {
        _certName = certName;
        _issuer = issuer;
        _subject = subject;
        _serialNumber = serialNumber;
        _version = version;
        _validFrom = validFrom;
        _validTo = validTo;
        _fingerPrint = fingerPrint;
        _trustCert = (trustCert != null) ? trustCert.equals("1") : false;
        _certDeleted =
                (certDeleted != null) ? certDeleted.equals("1") : false;
        _certTitle = certTitle;
    }

    public String getCertName() {
        return _certName;
    }
    public String getIssuer() {
        return _issuer;
    }
    public String getSubject() {
        return _subject;
    }
    public String getSerialNumber() {
        return _serialNumber;
    }
    public String getVersion() {
        return _version;
    }
    public String getValidFrom() {
        return _validFrom;
    }
    public String getValidTo() {
        return _validTo;
    }
    public String getFingerPrint() {
        return _fingerPrint;
    }
    public boolean trusted() {
        return _trustCert;
    }
    public boolean getCertDeleted() {
        return _certDeleted;
    }
    public String getCertTitle() {
        return _certTitle;
    }
}
