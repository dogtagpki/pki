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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cert;

import java.util.Date;

import com.netscape.cmscore.dbs.DBAttribute;
import com.netscape.cmscore.dbs.DBObjectClasses;
import com.netscape.cmscore.dbs.DBRecord;

/**
 * @author Endi S. Dewata
 */
@DBObjectClasses({ "top", "tokenCert" })
public class TPSCertRecord extends DBRecord {

    private static final long serialVersionUID = 1L;

    String id;
    String serialNumber;
    String subject;
    String tokenID;
    String keyType;
    String status;
    String userID;
    String certificate;
    String issuedBy;
    String origin;
    String type;
    Date validNotBefore;
    Date validNotAfter;
    String extensions;
    Date createTime;
    Date modifyTime;

    @DBAttribute("cn")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @DBAttribute("tokenSerial")
    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    @DBAttribute("tokenSubject")
    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    @DBAttribute("tokenID")
    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    @DBAttribute("tokenKeyType")
    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    @DBAttribute("tokenStatus")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @DBAttribute("tokenUserID")
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    @DBAttribute("userCertificate")
    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    @DBAttribute("tokenIssuer")
    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    @DBAttribute("tokenOrigin")
    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    @DBAttribute("tokenType")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @DBAttribute("tokenNotBefore")
    public Date getValidNotBefore() {
        return validNotBefore;
    }

    public void setValidNotBefore(Date validNotBefore) {
        this.validNotBefore = validNotBefore;
    }

    @DBAttribute("tokenNotAfter")
    public Date getValidNotAfter() {
        return validNotAfter;
    }

    public void setValidNotAfter(Date validNotAfter) {
        this.validNotAfter = validNotAfter;
    }

    @DBAttribute("extensions")
    public String getExtensions() {
        return extensions;
    }

    public void setExtensions(String extensions) {
        this.extensions = extensions;
    }

    @DBAttribute("dateOfCreate")
    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    @DBAttribute("dateOfModify")
    public Date getModifyTime() {
        return modifyTime;
    }

    public void setModifyTime(Date modifyTime) {
        this.modifyTime = modifyTime;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
        result = prime * result + ((createTime == null) ? 0 : createTime.hashCode());
        result = prime * result + ((extensions == null) ? 0 : extensions.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((issuedBy == null) ? 0 : issuedBy.hashCode());
        result = prime * result + ((keyType == null) ? 0 : keyType.hashCode());
        result = prime * result + ((modifyTime == null) ? 0 : modifyTime.hashCode());
        result = prime * result + ((origin == null) ? 0 : origin.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((tokenID == null) ? 0 : tokenID.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((userID == null) ? 0 : userID.hashCode());
        result = prime * result + ((validNotAfter == null) ? 0 : validNotAfter.hashCode());
        result = prime * result + ((validNotBefore == null) ? 0 : validNotBefore.hashCode());
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
        TPSCertRecord other = (TPSCertRecord) obj;
        if (certificate == null) {
            if (other.certificate != null)
                return false;
        } else if (!certificate.equals(other.certificate))
            return false;
        if (createTime == null) {
            if (other.createTime != null)
                return false;
        } else if (!createTime.equals(other.createTime))
            return false;
        if (extensions == null) {
            if (other.extensions != null)
                return false;
        } else if (!extensions.equals(other.extensions))
            return false;
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
        if (keyType == null) {
            if (other.keyType != null)
                return false;
        } else if (!keyType.equals(other.keyType))
            return false;
        if (modifyTime == null) {
            if (other.modifyTime != null)
                return false;
        } else if (!modifyTime.equals(other.modifyTime))
            return false;
        if (origin == null) {
            if (other.origin != null)
                return false;
        } else if (!origin.equals(other.origin))
            return false;
        if (serialNumber == null) {
            if (other.serialNumber != null)
                return false;
        } else if (!serialNumber.equals(other.serialNumber))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (subject == null) {
            if (other.subject != null)
                return false;
        } else if (!subject.equals(other.subject))
            return false;
        if (tokenID == null) {
            if (other.tokenID != null)
                return false;
        } else if (!tokenID.equals(other.tokenID))
            return false;
        if (type == null) {
            if (other.type != null)
                return false;
        } else if (!type.equals(other.type))
            return false;
        if (userID == null) {
            if (other.userID != null)
                return false;
        } else if (!userID.equals(other.userID))
            return false;
        if (validNotAfter == null) {
            if (other.validNotAfter != null)
                return false;
        } else if (!validNotAfter.equals(other.validNotAfter))
            return false;
        if (validNotBefore == null) {
            if (other.validNotBefore != null)
                return false;
        } else if (!validNotBefore.equals(other.validNotBefore))
            return false;
        return true;
    }
}
