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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
/**
 *
 */
package com.netscape.certsrv.cert;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertDataInfo implements JSONSerializer {

    CertId id;
    String subjectDN;
    String issuerDN;
    String status;
    String type;
    Integer version;
    String keyAlgorithmOID;
    Integer keyLength;
    Date notValidBefore;
    Date notValidAfter;
    Date issuedOn;
    String issuedBy;
    Date revokedOn;
    String revokedBy;

    Link link;

    public CertId getID() {
        return id;
    }

    public void setID(CertId id) {
        this.id = id;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public String getKeyAlgorithmOID() {
        return keyAlgorithmOID;
    }

    public void setKeyAlgorithmOID(String keyAlgorithmOID) {
        this.keyAlgorithmOID = keyAlgorithmOID;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    public Date getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(Date notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    public Date getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(Date notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    public Date getIssuedOn() {
        return issuedOn;
    }

    public void setIssuedOn(Date issuedOn) {
        this.issuedOn = issuedOn;
    }

    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    public Date getRevokedOn() {
        return revokedOn;
    }

    public void setRevokedOn(Date revokedOn) {
        this.revokedOn = revokedOn;
    }

    public String getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(String revokedBy) {
        this.revokedBy = revokedBy;
    }

    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((issuedBy == null) ? 0 : issuedBy.hashCode());
        result = prime * result + ((issuedOn == null) ? 0 : issuedOn.hashCode());
        result = prime * result + ((keyAlgorithmOID == null) ? 0 : keyAlgorithmOID.hashCode());
        result = prime * result + ((keyLength == null) ? 0 : keyLength.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
        result = prime * result + ((notValidAfter == null) ? 0 : notValidAfter.hashCode());
        result = prime * result + ((notValidBefore == null) ? 0 : notValidBefore.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
        result = prime * result + ((revokedOn == null) ? 0 : revokedOn.hashCode());
        result = prime * result + ((revokedBy == null) ? 0 : revokedBy.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertDataInfo other = (CertDataInfo) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (issuedBy == null) {
            if (other.issuedBy != null)
                return false;
        } else if (!issuedBy.equals(other.issuedBy))
            return false;
        if (issuedOn == null) {
            if (other.issuedOn != null)
                return false;
        } else if (!issuedOn.equals(other.issuedOn))
            return false;
        if (keyAlgorithmOID == null) {
            if (other.keyAlgorithmOID != null)
                return false;
        } else if (!keyAlgorithmOID.equals(other.keyAlgorithmOID))
            return false;
        if (keyLength == null) {
            if (other.keyLength != null)
                return false;
        } else if (!keyLength.equals(other.keyLength))
            return false;
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        if (notValidAfter == null) {
            if (other.notValidAfter != null)
                return false;
        } else if (!notValidAfter.equals(other.notValidAfter))
            return false;
        if (notValidBefore == null) {
            if (other.notValidBefore != null)
                return false;
        } else if (!notValidBefore.equals(other.notValidBefore))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (subjectDN == null) {
            if (other.subjectDN != null)
                return false;
        } else if (!subjectDN.equals(other.subjectDN))
            return false;
        if (issuerDN == null) {
            if (other.issuerDN != null) return false;
        } else if (!issuerDN.equals(other.issuerDN)) {
            return false;
        }
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        if (version == null) {
            if (other.version != null)
                return false;
        } else if (!version.equals(other.version))
            return false;
        if (revokedOn == null) {
            if (other.revokedOn != null)
                return false;
        } else if (!revokedOn.equals(other.revokedOn))
            return false;
        if (revokedBy == null) {
            if (other.revokedBy != null)
                return false;
        } else if (!revokedBy.equals(other.revokedBy))
            return false;
        return true;
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
