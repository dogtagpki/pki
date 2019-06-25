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

import java.util.List;

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
    protected String securityDomainType;

    @XmlElement
    protected String securityDomainUri;

    @XmlElement
    protected String securityDomainUser;

    @XmlElement
    protected String securityDomainPassword;

    @XmlElement(defaultValue="false")
    protected String isClone;

    @XmlElement
    protected String cloneUri;

    @XmlElement
    protected String hierarchy;

    @XmlElement
    protected Boolean systemCertsImported;

    @XmlElement
    protected List<SystemCertData> systemCerts;

    @XmlElement
    protected String issuingCA;

    @XmlElement
    protected Boolean external;

    @XmlElement
    protected String standAlone;

    @XmlElement(defaultValue = "true")
    protected String generateServerCert;

    @XmlElement(defaultValue="true")
    protected String generateSubsystemCert;

    /** Seconds to sleep after logging into the Security Domain,
     * so that replication of the session data may complete. */
    @XmlElement
    protected Long securityDomainPostLoginSleepSeconds;

    public ConfigurationRequest() {
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

    public String getSecurityDomainUri() {
        return securityDomainUri;
    }

    public void setSecurityDomainUri(String securityDomainUri) {
        this.securityDomainUri = securityDomainUri;
    }

    public String getSecurityDomainUser() {
        return securityDomainUser;
    }

    public void setSecurityDomainUser(String securityDomainUser) {
        this.securityDomainUser = securityDomainUser;
    }

    public String getSecurityDomainPassword() {
        return securityDomainPassword;
    }

    public void setSecurityDomainPassword(String securityDomainPassword) {
        this.securityDomainPassword = securityDomainPassword;
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

   public String getSystemCertKeyType(String tag) {
       SystemCertData cert = getSystemCert(tag);
       if(cert == null)
           return null;

       return cert.getKeyType();
   }

   /**
    *
    * @param systemCerts
    */
   public void setSystemCerts(List<SystemCertData> systemCerts) {
       this.systemCerts = systemCerts;
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

    public String getIsClone() {
        return isClone;
    }

    public void setIsClone(String isClone) {
        this.isClone = isClone;
    }

    public Long getSecurityDomainPostLoginSleepSeconds() {
        return securityDomainPostLoginSleepSeconds;
    }

    public void setSecurityDomainPostLoginSleepSeconds(Long d) {
        securityDomainPostLoginSleepSeconds = d;
    }

    @Override
    public String toString() {
        return "ConfigurationRequest [pin=XXXX" +
               ", securityDomainType=" + securityDomainType +
               ", securityDomainUri=" + securityDomainUri +
               ", securityDomainUser=" + securityDomainUser +
               ", securityDomainPassword=XXXX" +
               ", securityDomainPostLoginSleepSeconds=" + securityDomainPostLoginSleepSeconds +
               ", isClone=" + isClone +
               ", cloneUri=" + cloneUri +
               ", hierarchy=" + hierarchy +
               ", systemCertsImported=" + systemCertsImported +
               ", systemCerts=" + systemCerts +
               ", issuingCA=" + issuingCA +
               ", generateServerCert=" + generateServerCert +
               ", external=" + external +
               ", standAlone=" + standAlone +
               ", generateSubsystemCert=" + generateSubsystemCert +
               "]";
    }
}
