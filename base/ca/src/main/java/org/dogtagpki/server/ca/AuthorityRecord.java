//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

import org.mozilla.jss.netscape.security.x509.X500Name;

import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * @author Endi S. Dewata
 */
public class AuthorityRecord {

    AuthorityID authorityID;
    X500Name authorityDN;

    AuthorityID parentID;
    X500Name parentDN;

    String description;
    Boolean enabled;
    CertId serialNumber;

    /**
     * Sentinel prefix stored in authorityKeyNickname for externally-keyed CAs.
     *
     * An externally-keyed CA has its private key held outside Dogtag — for
     * example in an HSM attached to a remote ACME server.  Dogtag signs the
     * sub-CA certificate from a caller-supplied CSR and tracks the authority
     * for revocation purposes, but never performs signing operations for it.
     *
     * The sentinel is prefixed with '#' which is not a valid NSS token-name
     * character, so it cannot be mistaken for a real token:nickname pair.
     */
    public static final String EXTERNAL_KEY_NICKNAME_PREFIX = "#external#:";

    String keyNickname;
    Collection<String> keyHosts = new ArrayList<>();

    String nsUniqueID;
    BigInteger entryUSN;

    public AuthorityID getAuthorityID() {
        return authorityID;
    }

    public void setAuthorityID(AuthorityID authorityID) {
        this.authorityID = authorityID;
    }

    public X500Name getAuthorityDN() {
        return authorityDN;
    }

    public void setAuthorityDN(X500Name authorityDN) {
        this.authorityDN = authorityDN;
    }

    public AuthorityID getParentID() {
        return parentID;
    }

    public void setParentID(AuthorityID parentID) {
        this.parentID = parentID;
    }

    public X500Name getParentDN() {
        return parentDN;
    }

    public void setParentDN(X500Name parentDN) {
        this.parentDN = parentDN;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public CertId getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(CertId serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getKeyNickname() {
        return keyNickname;
    }

    public void setKeyNickname(String keyNickname) {
        this.keyNickname = keyNickname;
    }

    /**
     * Return true if this authority's private key is held externally.
     *
     * Externally-keyed authorities have a sentinel value in authorityKeyNickname
     * rather than a real NSS token:nickname pair.  Dogtag tracks them for
     * certificate issuance and revocation but does not perform signing for them.
     */
    public boolean isExternalKey() {
        return keyNickname != null
                && keyNickname.startsWith(EXTERNAL_KEY_NICKNAME_PREFIX);
    }

    public Collection<String> getKeyHosts() {
        return keyHosts;
    }

    public void setKeyHosts(Collection<String> keyHosts) {
        this.keyHosts.clear();
        this.keyHosts.addAll(keyHosts);
    }

    public void addKeyHost(String keyHost) {
        keyHosts.add(keyHost);
    }

    public void removeKeyHost(String keyHost) {
        keyHosts.remove(keyHost);
    }

    public String getNSUniqueID() {
        return nsUniqueID;
    }

    public void setNSUniqueID(String nsUniqueID) {
        this.nsUniqueID = nsUniqueID;
    }

    public BigInteger getEntryUSN() {
        return entryUSN;
    }

    public void setEntryUSN(BigInteger entryUSN) {
        this.entryUSN = entryUSN;
    }
}
