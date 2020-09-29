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
@XmlRootElement(name="SecurityDomainSetupRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class SecurityDomainSetupRequest {

    @XmlElement
    protected String pin;

    @XmlElement
    protected String securityDomainType;

    @XmlElement
    protected DomainInfo domainInfo;

    @XmlElement
    protected InstallToken installToken;

    @XmlElement(defaultValue="false")
    protected String clone;

    public SecurityDomainSetupRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getSecurityDomainType() {
        return securityDomainType;
    }

    public void setSecurityDomainType(String securityDomainType) {
        this.securityDomainType = securityDomainType;
    }

    public void setDomainInfo(DomainInfo domainInfo) {
        this.domainInfo = domainInfo;
    }

    public DomainInfo getDomainInfo() {
        return domainInfo;
    }

    public InstallToken getInstallToken() {
        return installToken;
    }

    public void setInstallToken(InstallToken installToken) {
        this.installToken = installToken;
    }

    public boolean isClone() {
        return "true".equalsIgnoreCase(clone);
    }

    public void setClone(String isClone) {
        this.clone = isClone;
    }

    @Override
    public String toString() {
        return "SecurityDomainSetupRequest [pin=XXXX" +
               ", securityDomainType=" + securityDomainType +
               ", clone=" + clone +
               "]";
    }
}
