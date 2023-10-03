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

    public Collection<String> getKeyHosts() {
        return keyHosts;
    }

    public void setKeyHosts(Collection<String> keyHosts) {
        this.keyHosts.clear();
        this.keyHosts.addAll(keyHosts);
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
