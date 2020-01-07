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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="ConfigurationRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class ConfigurationRequest {

    //defaults
    public static final String NEW_DOMAIN = "newdomain";
    public static final String EXISTING_DOMAIN = "existingdomain";
    public static final String NEW_SUBDOMAIN = "newsubdomain";

    @XmlElement
    protected String pin;

    @XmlElement
    protected DomainInfo domainInfo;

    @XmlElement
    protected InstallToken installToken;

    @XmlElement
    protected String securityDomainType;

    @XmlElement
    protected String securityDomainUri;

    @XmlElement(defaultValue="false")
    protected String isClone;

    @XmlElement
    protected String cloneUri;

    @XmlElement
    protected String hierarchy;

    @XmlElement
    protected Boolean systemCertsImported;

    @XmlElement
    protected String issuingCA;

    @XmlElement
    protected String standAlone;

    public ConfigurationRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
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

    public String getSecurityDomainType() {
        return securityDomainType;
    }

    public void setSecurityDomainType(String securityDomainType) {
        this.securityDomainType = securityDomainType;
    }

    public String getSecurityDomainUri() {
        return securityDomainUri;
    }

    public void setSecurityDomainUri(String securityDomainUri) {
        this.securityDomainUri = securityDomainUri;
    }

    public boolean isClone() {
        return (isClone!= null) && isClone.equalsIgnoreCase("true");
    }

    public void setClone(String isClone) {
        this.isClone = isClone;
    }

    public String getCloneUri() {
        return cloneUri;
    }

    public void setCloneUri(String cloneUri) {
        this.cloneUri = cloneUri;
    }

    /**
     * @return the hierarchy
     */
    public String getHierarchy() {
        return hierarchy;
    }

    /**
     * @param hierarchy the hierarchy to set
     */
    public void setHierarchy(String hierarchy) {
        this.hierarchy = hierarchy;
    }

    /**
     *
     * @return systemCertsImported
     */
    public Boolean getSystemCertsImported() {
        return systemCertsImported;
    }

    /**
     *
     * @param systemCertsImported
     */
    public void setSystemCertsImported(Boolean systemCertsImported) {
        this.systemCertsImported = systemCertsImported;
    }

   /**
     * @return the issuingCA
     */
    public String getIssuingCA() {
        return issuingCA;
    }

    /**
     * @param issuingCA the issuingCA to set
     */
    public void setIssuingCA(String issuingCA) {
        this.issuingCA = issuingCA;
    }

    public boolean getStandAlone() {
        return (standAlone != null && standAlone.equalsIgnoreCase("true"));
    }

    public void setStandAlone(String standAlone) {
        this.standAlone = standAlone;
    }

    public String getIsClone() {
        return isClone;
    }

    public void setIsClone(String isClone) {
        this.isClone = isClone;
    }

    @Override
    public String toString() {
        return "ConfigurationRequest [pin=XXXX" +
               ", installToken=XXXX" +
               ", securityDomainType=" + securityDomainType +
               ", securityDomainUri=" + securityDomainUri +
               ", isClone=" + isClone +
               ", cloneUri=" + cloneUri +
               ", hierarchy=" + hierarchy +
               ", systemCertsImported=" + systemCertsImported +
               ", issuingCA=" + issuingCA +
               ", standAlone=" + standAlone +
               "]";
    }
}
