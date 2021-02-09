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
    protected String adminCertRequest;

    @XmlElement
    protected String adminCertRequestType;

    @XmlElement
    protected String adminSubjectDN;

    @XmlElement
    protected String adminKeyType;

    @XmlElement
    protected String adminProfileID;

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

    @Override
    public String toString() {
        return "AdminSetupRequest [adminCertRequest=" + adminCertRequest +
               ", adminCertRequestType=" + adminCertRequestType +
               ", adminSubjectDN=" + adminSubjectDN +
               ", adminKeyType=" + adminKeyType +
               ", adminProfileID=" + adminProfileID +
               "]";
    }
}
