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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 * @author ftweedal
 */
package com.netscape.certsrv.authority;

import java.math.BigInteger;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class AuthorityData implements JSONSerializer {

    private Boolean isHostAuthority;

    public Boolean getIsHostAuthority() {
        return isHostAuthority;
    }

    public void setIsHostAuthority(Boolean isHostAuthority) {
        this.isHostAuthority = isHostAuthority;
    }

    private String id;

    public String getID() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    private String parentID;

    public String getParentID() {
        return parentID;
    }

    public void setParentID(String parentID) {
        this.parentID = parentID;
    }

    /* Read-only for existing CAs */
    private String issuerDN;

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /* Read-only attribute */
    private BigInteger serial;

    public BigInteger getSerial() {
        return serial;
    }


    public void setSerial(BigInteger serial) {
        this.serial = serial;
    }

    private String dn;

    public String getDN() {
        return dn;
    }

    public void setDn(String dn) {
        this.dn = dn;
    }

    private Boolean enabled;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    private String description;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * PEM-encoded PKCS#10 CSR for an externally-held CA key.
     *
     * When provided at creation time, Dogtag signs this CSR as a sub-CA
     * certificate without generating a local key pair.  The CA's private key
     * stays on the caller's side (e.g. in an HSM attached to an ACME server).
     * This field is consumed at creation and is not stored or returned
     * in subsequent GET responses.
     */
    private String csrData;

    public String getCsrData() {
        return csrData;
    }

    public void setCsrData(String csrData) {
        this.csrData = csrData;
    }

    /**
     * Signing profile to use when signing the external CSR (input-only).
     *
     * When present, overrides the default profile used by
     * {@link org.dogtagpki.server.ca.CAEngine#generateSigningCertFromCSR}.
     * Ignored when {@link #csrData} is absent.  Not stored or returned in
     * subsequent GET responses.
     *
     * <p>If absent, the engine defaults to {@code caExternalKeyCACert}.
     */
    private String profileId;

    public String getProfileId() {
        return profileId;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    /**
     * Whether this CA's private key is held externally (read-only).
     *
     * True when the authority was created with an external CSR.  Such a CA
     * is tracked by Dogtag for certificate issuance and revocation but is
     * never asked to perform signing operations locally.
     */
    private Boolean externalKey;

    public Boolean getExternalKey() {
        return externalKey;
    }

    public void setExternalKey(Boolean externalKey) {
        this.externalKey = externalKey;
    }

    /**
     * Whether the CA is ready to perform signing operations.
     *
     * This is a read-only attribute; it cannot be set by the user.
     */
    private Boolean ready;

    public Boolean getReady() {
        return ready;
    }

    public void setReady(Boolean ready) {
        this.ready = ready;
    }

    protected AuthorityData() {
    }

    public AuthorityData(
            Boolean isHostAuthority,
            String dn, String id, String parentID,
            String issuerDN, BigInteger serial,
            Boolean enabled, String description,
            Boolean ready) {
        this.setIsHostAuthority(isHostAuthority);
        this.setDn(dn);
        this.setId(id);
        this.setParentID(parentID);
        this.setIssuerDN(issuerDN);
        this.setSerial(serial);
        this.setEnabled(enabled);
        this.setDescription(description);
        this.setReady(ready);
    }

    @Override
    public int hashCode() {
        return Objects.hash(description, dn, enabled, externalKey, id, isHostAuthority, issuerDN, parentID, ready, serial);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AuthorityData other = (AuthorityData) obj;
        return Objects.equals(description, other.description) && Objects.equals(dn, other.dn)
                && Objects.equals(enabled, other.enabled) && Objects.equals(externalKey, other.externalKey)
                && Objects.equals(id, other.id)
                && Objects.equals(isHostAuthority, other.isHostAuthority) && Objects.equals(issuerDN, other.issuerDN)
                && Objects.equals(ready, other.ready) && Objects.equals(serial, other.serial);
    }

}
