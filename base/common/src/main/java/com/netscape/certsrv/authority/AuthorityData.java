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
import com.netscape.certsrv.base.Link;
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

    private Link link;

    public Link getLink() {
        return link;
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
        return Objects.hash(description, dn, enabled, id, isHostAuthority, issuerDN, link, parentID, ready, serial);
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
                && Objects.equals(enabled, other.enabled) && Objects.equals(id, other.id)
                && Objects.equals(isHostAuthority, other.isHostAuthority) && Objects.equals(issuerDN, other.issuerDN)
                && Objects.equals(link, other.link) && Objects.equals(parentID, other.parentID)
                && Objects.equals(ready, other.ready) && Objects.equals(serial, other.serial);
    }

}
