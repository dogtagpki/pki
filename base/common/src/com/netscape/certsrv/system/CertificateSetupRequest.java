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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="CertificateSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateSetupRequest {

    @XmlElement
    protected String pin;

    @XmlElement
    protected List<SystemCertData> systemCerts;

    @XmlElement
    protected Boolean external;

    @XmlElement
    protected String standAlone;

    @XmlElement(defaultValue = "true")
    protected String generateServerCert;

    @XmlElement(defaultValue="true")
    protected String generateSubsystemCert;

    public CertificateSetupRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    /**
    *
    * @return systemCerts
    */
   public List<SystemCertData> getSystemCerts() {
       return systemCerts;
   }

   public SystemCertData getSystemCert(String tag) {
       for (SystemCertData systemCert : systemCerts) {
           if (systemCert.getTag().equals(tag)) {
               return systemCert;
           }
       }
       return null;
   }

   /**
    *
    * @param systemCerts
    */
   public void setSystemCerts(List<SystemCertData> systemCerts) {
       this.systemCerts = systemCerts;
   }

    public Boolean isExternal() {
        return external;
    }

    public void setExternal(Boolean external) {
        this.external = external;
    }

    public boolean getStandAlone() {
        return (standAlone != null && standAlone.equalsIgnoreCase("true"));
    }

    public void setStandAlone(String standAlone) {
        this.standAlone = standAlone;
    }

    public String getGenerateServerCert() {
        return generateServerCert;
    }

    public void setGenerateServerCert(String generateServerCert) {
        this.generateServerCert = generateServerCert;
    }

    public boolean getGenerateSubsystemCert() {
        return generateSubsystemCert != null && generateSubsystemCert.equalsIgnoreCase("true");
    }

    public void setGenerateSubsystemCert(String generateSubsystemCert) {
        this.generateSubsystemCert = generateSubsystemCert;
    }

    @Override
    public String toString() {
        return "CertificateSetupRequest [pin=XXXX" +
               ", systemCerts=" + systemCerts +
               ", generateServerCert=" + generateServerCert +
               ", external=" + external +
               ", standAlone=" + standAlone +
               ", generateSubsystemCert=" + generateSubsystemCert +
               "]";
    }
}
