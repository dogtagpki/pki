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

package org.dogtagpki.server.tps.token;

import java.util.Date;

import com.netscape.cmscore.dbs.DBAttribute;
import com.netscape.cmscore.dbs.DBObjectClasses;
import com.netscape.cmscore.dbs.DBRecord;

/**
 * @author Endi S. Dewata
 */
@DBObjectClasses({ "top", "tokenRecord" })
public class TokenRecord extends DBRecord {

    private static final long serialVersionUID = 1L;

    String id;
    String userID;
    String status;
    String reason;
    String appletID;
    String keyInfo;
    Date createTimestamp;
    Date modifyTimestamp;

    @DBAttribute("cn")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @DBAttribute("tokenUserID")
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    @DBAttribute("tokenStatus")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @DBAttribute("tokenReason")
    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    @DBAttribute("tokenAppletID")
    public String getAppletID() {
        return appletID;
    }

    public void setAppletID(String appletID) {
        this.appletID = appletID;
    }

    @DBAttribute("keyInfo")
    public String getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(String keyInfo) {
        this.keyInfo = keyInfo;
    }

    @DBAttribute("dateOfCreate")
    public Date getCreateTimestamp() {
        return createTimestamp;
    }

    public void setCreateTimestamp(Date createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    @DBAttribute("dateOfModify")
    public Date getModifyTimestamp() {
        return modifyTimestamp;
    }

    public void setModifyTimestamp(Date modifyTimestamp) {
        this.modifyTimestamp = modifyTimestamp;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((appletID == null) ? 0 : appletID.hashCode());
        result = prime * result + ((createTimestamp == null) ? 0 : createTimestamp.hashCode());
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((keyInfo == null) ? 0 : keyInfo.hashCode());
        result = prime * result + ((modifyTimestamp == null) ? 0 : modifyTimestamp.hashCode());
        result = prime * result + ((reason == null) ? 0 : reason.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((userID == null) ? 0 : userID.hashCode());
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
        TokenRecord other = (TokenRecord) obj;
        if (appletID == null) {
            if (other.appletID != null)
                return false;
        } else if (!appletID.equals(other.appletID))
            return false;
        if (createTimestamp == null) {
            if (other.createTimestamp != null)
                return false;
        } else if (!createTimestamp.equals(other.createTimestamp))
            return false;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (keyInfo == null) {
            if (other.keyInfo != null)
                return false;
        } else if (!keyInfo.equals(other.keyInfo))
            return false;
        if (modifyTimestamp == null) {
            if (other.modifyTimestamp != null)
                return false;
        } else if (!modifyTimestamp.equals(other.modifyTimestamp))
            return false;
        if (reason == null) {
            if (other.reason != null)
                return false;
        } else if (!reason.equals(other.reason))
            return false;
        if (status == null) {
            if (other.status != null)
                return false;
        } else if (!status.equals(other.status))
            return false;
        if (userID == null) {
            if (other.userID != null)
                return false;
        } else if (!userID.equals(other.userID))
            return false;
        return true;
    }
}
