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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

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

    @XmlElement
    protected String authdbBaseDN;

    @XmlElement
    protected String authdbHost;

    @XmlElement
    protected String authdbPort;

    @XmlElement(defaultValue="false")
    protected String authdbSecureConn;

    @XmlElement
    @XmlJavaTypeAdapter(URIAdapter.class)
    protected URI caUri;

    @XmlElement
    @XmlJavaTypeAdapter(URIAdapter.class)
    protected URI tksUri;

    @XmlElement
    @XmlJavaTypeAdapter(URIAdapter.class)
    protected URI kraUri;

    @XmlElement(defaultValue="false")
    protected String enableServerSideKeyGen;

    @XmlElement(defaultValue="false")
    protected String importSharedSecret;

    @XmlElement(defaultValue="true")
    protected String generateSubsystemCert;

    @XmlElement
    protected String startingCRLNumber;

    @XmlElement
    protected Boolean createSigningCertRecord;

    @XmlElement
    protected String signingCertSerialNumber;

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

    public String getAuthdbBaseDN() {
        return authdbBaseDN;
    }

    public void setAuthdbBaseDN(String authdbBaseDN) {
        this.authdbBaseDN = authdbBaseDN;
    }

    public String getAuthdbHost() {
        return authdbHost;
    }

    public void setAuthdbHost(String authdbHost) {
        this.authdbHost = authdbHost;
    }

    public String getAuthdbPort() {
        return authdbPort;
    }

    public void setAuthdbPort(String authdbPort) {
        this.authdbPort = authdbPort;
    }

    public String getAuthdbSecureConn() {
        return authdbSecureConn;
    }

    public void setAuthdbSecureConn(String authdbSecureConn) {
        this.authdbSecureConn = authdbSecureConn;
    }

    public URI getCaUri() {
        return caUri;
    }

    public void setCaUri(URI caUri) {
        this.caUri = caUri;
    }

    public URI getTksUri() {
        return tksUri;
    }

    public void setTksUri(URI tksUri) {
        this.tksUri = tksUri;
    }

    public URI getKraUri() {
        return kraUri;
    }

    public void setKraUri(URI kraUri) {
        this.kraUri = kraUri;
    }

    public String getEnableServerSideKeyGen() {
        return enableServerSideKeyGen;
    }

    public void setEnableServerSideKeyGen(String enableServerSideKeyGen) {
        this.enableServerSideKeyGen = enableServerSideKeyGen;
    }

    public String getImportSharedSecret() {
        return importSharedSecret;
    }

    public void setImportSharedSecret(String importSharedSecret) {
        this.importSharedSecret = importSharedSecret;
    }

    public boolean getGenerateSubsystemCert() {
        return generateSubsystemCert != null && generateSubsystemCert.equalsIgnoreCase("true");
    }

    public void setGenerateSubsystemCert(String generateSubsystemCert) {
        this.generateSubsystemCert = generateSubsystemCert;
    }

    public String getStartingCRLNumber() {
        return startingCRLNumber;
    }

    public void setStartingCRLNumber(String startingCRLNumber) {
        this.startingCRLNumber = startingCRLNumber;
    }

    public String getIsClone() {
        return isClone;
    }

    public void setIsClone(String isClone) {
        this.isClone = isClone;
    }

    public Boolean createSigningCertRecord() {
        return createSigningCertRecord;
    }

    public void setCreateSigningCertRecord(Boolean createSigningCertRecord) {
        this.createSigningCertRecord = createSigningCertRecord;
    }

    public String getSigningCertSerialNumber() {
        return signingCertSerialNumber;
    }

    public void setSigningCertSerialNumber(String signingCertSerialNumber) {
        this.signingCertSerialNumber = signingCertSerialNumber;
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
               ", authdbBaseDN=" + authdbBaseDN +
               ", authdbHost=" + authdbHost +
               ", authdbPort=" + authdbPort +
               ", authdbSecureConn=" + authdbSecureConn +
               ", caUri=" + caUri +
               ", kraUri=" + kraUri +
               ", tksUri=" + tksUri +
               ", enableServerSideKeyGen=" + enableServerSideKeyGen +
               ", importSharedSecret=" + importSharedSecret +
               ", generateSubsystemCert=" + generateSubsystemCert +
               ", startingCrlNumber=" + startingCRLNumber +
               ", createSigningCertRecord=" + createSigningCertRecord +
               ", signingCertSerialNumber=" + signingCertSerialNumber +
               "]";
    }

    public static class URIAdapter extends XmlAdapter<String, URI> {

        public String marshal(URI uri) {
            return uri == null ? null : uri.toString();
        }

        public URI unmarshal(String uri) throws URISyntaxException {
            return uri == null ? null : new URI(uri);
        }
    }
}
