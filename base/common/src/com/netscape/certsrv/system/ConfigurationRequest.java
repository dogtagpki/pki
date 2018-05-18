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

import com.netscape.cmsutil.crypto.CryptoUtil;

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

    // Hard coded values for ECC and RSA internal cert profile names
    public static final String ECC_INTERNAL_SERVER_CERT_PROFILE = "caECInternalAuthServerCert";
    public static final String RSA_INTERNAL_SERVER_CERT_PROFILE = "caInternalAuthServerCert";

    public static final String ECC_INTERNAL_SUBSYSTEM_CERT_PROFILE= "caECInternalAuthSubsystemCert";
    public static final String RSA_INTERNAL_SUBSYSTEM_CERT_PROFILE= "caInternalAuthSubsystemCert";

    public static final String ECC_INTERNAL_ADMIN_CERT_PROFILE="caECAdminCert";
    public static final String RSA_INTERNAL_ADMIN_CERT_PROFILE="caAdminCert";

    @XmlElement
    protected String pin;

    @XmlElement(defaultValue=CryptoUtil.INTERNAL_TOKEN_FULL_NAME)
    protected String token;

    @XmlElement
    protected String tokenPassword;

    @XmlElement
    protected String securityDomainType;

    @XmlElement
    protected String securityDomainUri;

    @XmlElement
    protected String securityDomainName;

    @XmlElement
    protected String securityDomainUser;

    @XmlElement
    protected String securityDomainPassword;

    @XmlElement(defaultValue="false")
    protected String isClone;

    @XmlElement
    protected String cloneUri;

    @XmlElement
    protected String subsystemName;

    @XmlElement
    protected String p12File;

    @XmlElement
    protected String p12Password;

    @XmlElement
    protected String hierarchy;

    @XmlElement
    protected String dsHost;

    @XmlElement
    protected String dsPort;

    @XmlElement
    protected String baseDN;

    @XmlElement
    protected String createNewDB;

    @XmlElement
    protected String bindDN;

    @XmlElement
    protected String bindpwd;

    @XmlElement
    protected String database;

    @XmlElement(defaultValue = "false")
    protected String secureConn;

    @XmlElement
    protected String removeData;

    @XmlElement
    protected String masterReplicationPort;

    @XmlElement
    protected String cloneReplicationPort;

    @XmlElement
    protected String replicateSchema;

    @XmlElement
    protected String replicationSecurity;

    @XmlElement
    protected String replicationPassword;

    @XmlElement
    protected String setupReplication;

    @XmlElement
    protected String reindexData;

    @XmlElement
    protected Boolean systemCertsImported;

    @XmlElement
    protected List<SystemCertData> systemCerts;

    @XmlElement
    protected String issuingCA;

    @XmlElement
    protected String backupKeys;

    @XmlElement
    protected String backupPassword;

    @XmlElement
    protected String backupFile;

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
    protected String adminProfileID;

    @XmlElement(defaultValue = "false")
    protected String importAdminCert;

    @XmlElement
    protected String adminCert;

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

    @XmlElement(defaultValue="false")
    protected String sharedDB;

    @XmlElement
    protected String subordinateSecurityDomainName;

    @XmlElement
    protected String sharedDBUserDN;

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

    public String getSubsystemName() {
        return subsystemName;
    }

    public void setSubsystemName(String subsystemName) {
        this.subsystemName = subsystemName;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
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

    public String getSecurityDomainName() {
        return securityDomainName;
    }

    public void setSecurityDomainName(String securityDomainName) {
        this.securityDomainName = securityDomainName;
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
     * @return the p12File
     */
    public String getP12File() {
        return p12File;
    }

    /**
     * @param p12File the p12File to set
     */
    public void setP12File(String p12File) {
        this.p12File = p12File;
    }

    /**
     * @return the p12Password
     */
    public String getP12Password() {
        return p12Password;
    }

    /**
     * @param p12Password the p12Password to set
     */
    public void setP12Password(String p12Password) {
        this.p12Password = p12Password;
    }

    /**
     * @return the tokenPassword
     */
    public String getTokenPassword() {
        return tokenPassword;
    }

    /**
     * @param tokenPassword the tokenPassword to set
     */
    public void setTokenPassword(String tokenPassword) {
        this.tokenPassword = tokenPassword;
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
     * @return the dsHost
     */
    public String getDsHost() {
        return dsHost;
    }

    /**
     * @param dsHost the dsHost to set
     */
    public void setDsHost(String dsHost) {
        this.dsHost = dsHost;
    }

    /**
     * @return the dsPort
     */
    public String getDsPort() {
        return dsPort;
    }

    /**
     * @param dsPort the dsPort to set
     */
    public void setDsPort(String dsPort) {
        this.dsPort = dsPort;
    }

    /**
     * @return the baseDN
     */
    public String getBaseDN() {
        return baseDN;
    }

    /**
     * @param baseDN the baseDN to set
     */
    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }

    /**
     * @return the bindDN
     */
    public String getBindDN() {
        return bindDN;
    }

    /**
     * @param bindDN the bindDN to set
     */
    public void setBindDN(String bindDN) {
        this.bindDN = bindDN;
    }

    /**
     * @return the bindpwd
     */
    public String getBindpwd() {
        return bindpwd;
    }

    /**
     * @param bindpwd the bindpwd to set
     */
    public void setBindpwd(String bindpwd) {
        this.bindpwd = bindpwd;
    }

    /**
     * @return the secureConn
     */
    public String getSecureConn() {
        return secureConn;
    }

    /**
     * @param secureConn the secureConn to set
     */
    public void setSecureConn(String secureConn) {
        this.secureConn = secureConn;
    }

    /**
     * @return the removeData
     */
    public String getRemoveData() {
        return removeData;
    }

    /**
     * @param removeData the removeData to set
     */
    public void setRemoveData(String removeData) {
        this.removeData = removeData;
    }

    /**
     * @return the masterReplicationPort
     */
    public String getMasterReplicationPort() {
        return masterReplicationPort;
    }

    /**
     * @param masterReplicationPort the masterReplicationPort to set
     */
    public void setMasterReplicationPort(String masterReplicationPort) {
        this.masterReplicationPort = masterReplicationPort;
    }

    /**
     * @return the cloneReplicationPort
     */
    public String getCloneReplicationPort() {
        return cloneReplicationPort;
    }

    /**
     * @param cloneReplicationPort the cloneReplicationPort to set
     */
    public void setCloneReplicationPort(String cloneReplicationPort) {
        this.cloneReplicationPort = cloneReplicationPort;
    }

    /**
     * @return the replicationSecurity
     */
    public String getReplicationSecurity() {
        return replicationSecurity;
    }

    /**
     * @param replicationSecurity the replicationSecurity to set
     */
    public void setReplicationSecurity(String replicationSecurity) {
        this.replicationSecurity = replicationSecurity;
    }

    public String getReplicationPassword() {
        return replicationPassword;
    }

    public void setReplicationPassword(String replicationPassword) {
        this.replicationPassword = replicationPassword;
    }

    public boolean getSetupReplication() {
        // default to true
        if (setupReplication == null) {
            return true;
        }
        return setupReplication.equalsIgnoreCase("true");
    }

    public void setSetupReplication(String setupReplication) {
        this.setupReplication = setupReplication;
    }

    public boolean getReindexData() {
        // default to false
        if (reindexData == null) {
            return false;
        }
        return reindexData.equalsIgnoreCase("true");
    }

    public void setReindexData(String reindexData) {
        this.reindexData = reindexData;
    }

    /**
     * @return the database
     */
    public String getDatabase() {
        return database;
    }

    /**
     * @param database the database to set
     */
    public void setDatabase(String database) {
        this.database = database;
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

    public String getSystemCertProfileID(String tag, String defaultName) {
        String profileName = defaultName;
        String keyType = getSystemCertKeyType(tag);

        System.out.println("getSystemCertProfileID tag: " + tag + " defaultName: " + defaultName + " keyType: " + keyType);
        if (keyType == null)
            return profileName;

        // Hard code for now based on key type.  Method can be changed later to read pkispawn
        // params sent over in the future.
        if ("ecc".equalsIgnoreCase(keyType)) {
            if ("sslserver".equalsIgnoreCase(tag)) {
                profileName = ECC_INTERNAL_SERVER_CERT_PROFILE;
            } else if ("subsystem".equalsIgnoreCase(tag)) {
                profileName = ECC_INTERNAL_SUBSYSTEM_CERT_PROFILE;
            }
        } else if ("rsa".equalsIgnoreCase(keyType)) {
            if ("sslserver".equalsIgnoreCase(tag)) {
                profileName = RSA_INTERNAL_SERVER_CERT_PROFILE;
            } else if ("subsystem".equalsIgnoreCase(tag)) {
                profileName = RSA_INTERNAL_SUBSYSTEM_CERT_PROFILE;
            }
        }

        System.out.println("getSystemCertProfileID: returning: " + profileName);
        return profileName;
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

    /**
     * @return the backupKeys
     */
    public String getBackupKeys() {
        return backupKeys;
    }

    /**
     * @param backupKeys the backupKeys to set
     */
    public void setBackupKeys(String backupKeys) {
        this.backupKeys = backupKeys;
    }

    /**
     * @return the backupFile
     */
    public String getBackupFile() {
        return backupFile;
    }

    /**
     * @param backupFile the backupFile to set
     */
    public void setBackupFile(String backupFile) {
        this.backupFile = backupFile;
    }

    /**
     * @return the backupPassword
     */
    public String getBackupPassword() {
        return backupPassword;
    }

    /**
     * @param backupPassword the backupPassword to set
     */
    public void setBackupPassword(String backupPassword) {
        this.backupPassword = backupPassword;
    }

    /**
     * @return the adminUID
     */
    public String getAdminUID() {
        return adminUID;
    }

    /**
     * @param adminUID the adminUID to set
     */
    public void setAdminUID(String adminUID) {
        this.adminUID = adminUID;
    }

    /**
     * @return the adminPassword
     */
    public String getAdminPassword() {
        return adminPassword;
    }

    /**
     * @param adminPassword the adminPassword to set
     */
    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    /**
     * @return the adminEmail
     */
    public String getAdminEmail() {
        return adminEmail;
    }

    /**
     * @param adminEmail the adminEmail to set
     */
    public void setAdminEmail(String adminEmail) {
        this.adminEmail = adminEmail;
    }

    /**
     * @return the adminCertRequest
     */
    public String getAdminCertRequest() {
        return adminCertRequest;
    }

    /**
     * @param adminCertRequest the adminCertRequest to set
     */
    public void setAdminCertRequest(String adminCertRequest) {
        this.adminCertRequest = adminCertRequest;
    }

    /**
     * @return the adminCertRequestType
     */
    public String getAdminCertRequestType() {
        return adminCertRequestType;
    }

    /**
     * @param adminCertRequestType the adminCertRequestType to set
     */
    public void setAdminCertRequestType(String adminCertRequestType) {
        this.adminCertRequestType = adminCertRequestType;
    }

    /**
     * @return the adminSubjectDN
     */
    public String getAdminSubjectDN() {
        return adminSubjectDN;
    }

    /**
     * @param adminSubjectDN the adminSubjectDN to set
     */
    public void setAdminSubjectDN(String adminSubjectDN) {
        this.adminSubjectDN = adminSubjectDN;
    }

    /**
     * @return the adminName
     */
    public String getAdminName() {
        return adminName;
    }

    /**
     * @param adminName the adminName to set
     */
    public void setAdminName(String adminName) {
        this.adminName = adminName;
    }

    /**
     * @return the adminProfileID
     */
    public String getAdminProfileID() {

        // Modify the value returned based on key type of the
        // subsystem cert. If keyType not found take the default
        // sent over the server. In the future we can make sure
        // the correct value is sent over the server.
        String keyType = this.getSystemCertKeyType("subsystem");
        String actualAdminProfileID = adminProfileID;
        if(keyType != null) {
            if("ecc".equalsIgnoreCase(keyType)) {
                actualAdminProfileID = ECC_INTERNAL_ADMIN_CERT_PROFILE;
            } else if("rsa".equalsIgnoreCase(keyType)) {
                actualAdminProfileID = RSA_INTERNAL_ADMIN_CERT_PROFILE;
            }
        }

        return actualAdminProfileID;
    }

    /**
     * @param adminProfileID the adminProfileID to set
     */
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

    public String getReplicateSchema() {
        return replicateSchema;
    }

    public void setReplicateSchema(String replicateSchema) {
        this.replicateSchema = replicateSchema;
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

    public boolean getSharedDB() {
        return sharedDB != null && sharedDB.equalsIgnoreCase("true");
    }

    public void setSharedDB(String sharedDB) {
        this.sharedDB = sharedDB;
    }

    public String getSharedDBUserDN() {
        return sharedDBUserDN;
    }

    public void setSharedDBUserDN(String sharedDBUserDN) {
        this.sharedDBUserDN = sharedDBUserDN;
    }

    public boolean getCreateNewDB() {
        // default to true
        if (createNewDB == null) {
            return true;
        }
        return createNewDB.equalsIgnoreCase("true");
    }

    public void setCreateNewDB(String createNewDB) {
        this.createNewDB = createNewDB;
    }

    public String getSubordinateSecurityDomainName() {
        return subordinateSecurityDomainName;
    }

    public void setSubordinateSecurityDomainName(String subordinateSecurityDomainName) {
        this.subordinateSecurityDomainName = subordinateSecurityDomainName;
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
               ", token=" + token + ", tokenPassword=XXXX" +
               ", securityDomainType=" + securityDomainType +
               ", securityDomainUri=" + securityDomainUri +
               ", securityDomainName=" + securityDomainName +
               ", securityDomainUser=" + securityDomainUser +
               ", securityDomainPassword=XXXX" +
               ", securityDomainPostLoginSleepSeconds=" + securityDomainPostLoginSleepSeconds +
               ", isClone=" + isClone +
               ", cloneUri=" + cloneUri +
               ", subsystemName=" + subsystemName +
               ", p12File=" + p12File +
               ", p12Password=XXXX" +
               ", hierarchy=" + hierarchy +
               ", dsHost=" + dsHost +
               ", dsPort=" + dsPort +
               ", baseDN=" + baseDN +
               ", bindDN=" + bindDN +
               ", bindpwd=XXXX" +
               ", database=" + database +
               ", secureConn=" + secureConn +
               ", removeData=" + removeData +
               ", replicateSchema=" + replicateSchema +
               ", masterReplicationPort=" + masterReplicationPort +
               ", cloneReplicationPort=" + cloneReplicationPort +
               ", replicationSecurity=" + replicationSecurity +
               ", systemCertsImported=" + systemCertsImported +
               ", systemCerts=" + systemCerts +
               ", issuingCA=" + issuingCA +
               ", backupKeys=" + backupKeys +
               ", backupPassword=XXXX" +
               ", backupFile=" + backupFile +
               ", adminUID=" + adminUID +
               ", adminPassword=XXXX" +
               ", adminEmail=" + adminEmail +
               ", adminCertRequest=" + adminCertRequest +
               ", adminCertRequestType=" + adminCertRequestType +
               ", adminSubjectDN=" + adminSubjectDN +
               ", adminName=" + adminName +
               ", adminProfileID=" + adminProfileID +
               ", adminCert=" + adminCert +
               ", importAdminCert=" + importAdminCert +
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
               ", sharedDB=" +  sharedDB +
               ", sharedDBUserDN=" + sharedDBUserDN +
               ", createNewDB=" + createNewDB +
               ", setupReplication=" + setupReplication +
               ", subordinateSecurityDomainName=" + subordinateSecurityDomainName +
               ", reindexData=" + reindexData +
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
