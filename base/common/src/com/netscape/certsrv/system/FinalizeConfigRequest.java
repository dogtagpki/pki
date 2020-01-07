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

import java.net.URI;
import java.net.URISyntaxException;

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
@XmlRootElement(name="FinalizeConfigRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class FinalizeConfigRequest {

    @XmlElement
    protected String pin;

    @XmlElement
    protected String securityDomainUri;

    @XmlElement
    protected DomainInfo domainInfo;

    @XmlElement
    protected InstallToken installToken;

    @XmlElement(defaultValue="false")
    protected String isClone;

    @XmlElement
    protected String cloneUri;

    @XmlElement
    protected String standAlone;

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

    @XmlElement
    protected String startingCRLNumber;

    @XmlElement
    protected Boolean createSigningCertRecord;

    @XmlElement
    protected String signingCertSerialNumber;

    public FinalizeConfigRequest() {
        // required for JAXB
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getSecurityDomainUri() {
        return securityDomainUri;
    }

    public void setSecurityDomainUri(String securityDomainUri) {
        this.securityDomainUri = securityDomainUri;
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
        return (isClone!= null) && isClone.equalsIgnoreCase("true");
    }

    public void setClone(String isClone) {
        this.isClone = isClone;
    }

    public String getIsClone() {
        return isClone;
    }

    public void setIsClone(String isClone) {
        this.isClone = isClone;
    }

    public String getCloneUri() {
        return cloneUri;
    }

    public void setCloneUri(String cloneUri) {
        this.cloneUri = cloneUri;
    }

    public boolean getStandAlone() {
        return (standAlone != null && standAlone.equalsIgnoreCase("true"));
    }

    public void setStandAlone(String standAlone) {
        this.standAlone = standAlone;
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

    public String getStartingCRLNumber() {
        return startingCRLNumber;
    }

    public void setStartingCRLNumber(String startingCRLNumber) {
        this.startingCRLNumber = startingCRLNumber;
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

    @Override
    public String toString() {
        return "FinalizeConfigRequest [pin=XXXX" +
               ", securityDomainUri=" + securityDomainUri +
               ", isClone=" + isClone +
               ", cloneUri=" + cloneUri +
               ", standAlone=" + standAlone +
               ", caUri=" + caUri +
               ", kraUri=" + kraUri +
               ", tksUri=" + tksUri +
               ", enableServerSideKeyGen=" + enableServerSideKeyGen +
               ", importSharedSecret=" + importSharedSecret +
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
