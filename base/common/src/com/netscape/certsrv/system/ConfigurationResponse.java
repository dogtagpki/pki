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
package com.netscape.certsrv.system;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;

/**
 * @author alee
 *
 */
@XmlRootElement(name="ConfigurationResponse")
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigurationResponse {

    @XmlElement
    protected List<SystemCertData> systemCerts;

    @XmlElement
    protected SystemCertData adminCert;

    @XmlElement
    protected String status;

    public ConfigurationResponse() {
        systemCerts = new ArrayList<SystemCertData>();
        adminCert = new SystemCertData();
    }

    /**
     * @return the systemCerts
     */
    public List<SystemCertData> getSystemCerts() {
        return systemCerts;
    }

    /**
     * @param systemCerts the systemCerts to set
     */
    public void setSystemCerts(List<SystemCertData> systemCerts) {
        this.systemCerts = systemCerts;
    }

    /**
     * @return the adminCert
     */
    public SystemCertData getAdminCert() {
        return adminCert;
    }

    /**
     * @param adminCert the adminCert to set
     */
    public void setAdminCert(SystemCertData adminCert) {
        this.adminCert = adminCert;
    }

    /**
     * @return the status
     */
    public String getStatus() {
        return status;
    }

    /**
     * @param status the status to set
     */
    public void setStatus(String status) {
        this.status = status;
    }



    public void setAdminCert(X509CertImpl x509CertImpl) throws CertificateEncodingException {
        adminCert.setCert(CMS.BtoA(x509CertImpl.getEncoded()));
    }

}
