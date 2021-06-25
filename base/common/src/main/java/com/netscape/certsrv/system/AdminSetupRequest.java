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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Objects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@XmlRootElement(name="AdminSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class AdminSetupRequest implements JSONSerializer {

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

    @Override
    public int hashCode() {
        return Objects.hash(adminCertRequest, adminCertRequestType, adminKeyType, adminProfileID, adminSubjectDN,
                installToken, pin);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AdminSetupRequest other = (AdminSetupRequest) obj;
        return Objects.equals(adminCertRequest, other.adminCertRequest)
                && Objects.equals(adminCertRequestType, other.adminCertRequestType)
                && Objects.equals(adminKeyType, other.adminKeyType)
                && Objects.equals(adminProfileID, other.adminProfileID)
                && Objects.equals(adminSubjectDN, other.adminSubjectDN)
                && Objects.equals(installToken, other.installToken)
                && Objects.equals(pin, other.pin);
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(AdminSetupRequest.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static AdminSetupRequest fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(AdminSetupRequest.class).createUnmarshaller();
        return (AdminSetupRequest) unmarshaller.unmarshal(new StringReader(xml));
    }

}
