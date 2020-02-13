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
    protected InstallToken installToken;

    @XmlElement
    protected String tag;

    @XmlElement
    protected SystemCertData systemCert;

    @XmlElement
    protected Boolean external;

    @XmlElement
    protected String standAlone;

    @XmlElement(defaultValue = "true")
    protected String generateServerCert;

    @XmlElement(defaultValue="true")
    protected String generateSubsystemCert;

    @XmlElement(defaultValue="false")
    protected String clone;

    public CertificateSetupRequest() {
        // required for JAXB
    }

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

    public String getTag() {
        return tag;
    }

    public void setTag(String tag) {
        this.tag = tag;
    }

   public SystemCertData getSystemCert() {
       return systemCert;
   }

   public void setSystemCert(SystemCertData systemCert) {
       this.systemCert = systemCert;
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

    public boolean isClone() {
        return "true".equalsIgnoreCase(clone);
    }

    public void setClone(String isClone) {
        this.clone = isClone;
    }

    @Override
    public String toString() {
        return "CertificateSetupRequest [pin=XXXX" +
               ", tag=" + tag +
               ", systemCert=" + systemCert +
               ", generateServerCert=" + generateServerCert +
               ", external=" + external +
               ", standAlone=" + standAlone +
               ", generateSubsystemCert=" + generateSubsystemCert +
               ", clone=" + clone +
               "]";
    }
}
