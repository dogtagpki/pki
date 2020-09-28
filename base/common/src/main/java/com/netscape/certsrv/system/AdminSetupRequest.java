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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="AdminSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class AdminSetupRequest {

    @XmlElement
    protected String pin;

    @XmlElement
    protected InstallToken installToken;

    @XmlElement
    protected String adminUID;

    @XmlElement
    protected String adminPassword;

    @XmlElement
    protected String adminEmail;

    @XmlElement
    protected String adminCertRequest;

    @XmlElement
    protected String adminCertRequestType;

    @XmlElement
    protected String adminSubjectDN;

    @XmlElement
    protected String adminName;

    @XmlElement
    protected String adminKeyType;

    @XmlElement
    protected String adminProfileID;

    @XmlElement(defaultValue = "false")
    protected String importAdminCert;

    @XmlElement
    protected String adminCert;

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public InstallToken getInstallToken() {
        return installToken;
    }

    public void setInstallToken(InstallToken installToken) {
        this.installToken = installToken;
    }

    public String getAdminUID() {
        return adminUID;
    }

    public void setAdminUID(String adminUID) {
        this.adminUID = adminUID;
    }

    public String getAdminPassword() {
        return adminPassword;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    public String getAdminEmail() {
        return adminEmail;
    }

    public void setAdminEmail(String adminEmail) {
        this.adminEmail = adminEmail;
    }

    public String getAdminCertRequest() {
        return adminCertRequest;
    }

    public void setAdminCertRequest(String adminCertRequest) {
        this.adminCertRequest = adminCertRequest;
    }

    public String getAdminCertRequestType() {
        return adminCertRequestType;
    }

    public void setAdminCertRequestType(String adminCertRequestType) {
        this.adminCertRequestType = adminCertRequestType;
    }

    public String getAdminSubjectDN() {
        return adminSubjectDN;
    }

    public void setAdminSubjectDN(String adminSubjectDN) {
        this.adminSubjectDN = adminSubjectDN;
    }

    public String getAdminName() {
        return adminName;
    }

    public void setAdminName(String adminName) {
        this.adminName = adminName;
    }

    /**
     * @return the admin key type
     */
    public String getAdminKeyType() {
        return adminKeyType;
    }

    /**
     * @param adminKeyType the admin key type
     */
    public void setAdminKeyType(String adminKeyType) {
        this.adminKeyType = adminKeyType;
    }

    public String getAdminProfileID() {
        return adminProfileID;
    }

    public void setAdminProfileID(String adminProfileID) {
        this.adminProfileID = adminProfileID;
    }

    public String getImportAdminCert() {
        return importAdminCert;
    }

    public void setImportAdminCert(String importAdminCert) {
        this.importAdminCert = importAdminCert;
    }

    public String getAdminCert() {
        return adminCert;
    }

    public void setAdminCert(String adminCert) {
        this.adminCert = adminCert;
    }

    @Override
    public String toString() {
        return "AdminSetupRequest [adminUID=" + adminUID +
               ", adminPassword=XXXX" +
               ", adminEmail=" + adminEmail +
               ", adminCertRequest=" + adminCertRequest +
               ", adminCertRequestType=" + adminCertRequestType +
               ", adminSubjectDN=" + adminSubjectDN +
               ", adminName=" + adminName +
               ", adminKeyType=" + adminKeyType +
               ", adminProfileID=" + adminProfileID +
               ", adminCert=" + adminCert +
               ", importAdminCert=" + importAdminCert +
               "]";
    }
}
