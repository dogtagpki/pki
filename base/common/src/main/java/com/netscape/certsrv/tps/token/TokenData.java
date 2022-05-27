
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

package com.netscape.certsrv.tps.token;

import java.util.Collection;
import java.util.Date;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TokenData implements JSONSerializer {

    public static class TokenStatusData {

        @Override
        public int hashCode() {
            return Objects.hash(label, name);
        }
        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            TokenStatusData other = (TokenStatusData) obj;
            return Objects.equals(label, other.label) && Objects.equals(name, other.name);
        }
        public TokenStatus name;
        public String label;

    }

    String id;
    @JsonProperty("TokenID")
    String tokenID;
    @JsonProperty("UserID")
    String userID;
    @JsonProperty("Type")
    String type;

    @JsonProperty("Status")
    TokenStatusData status;
    @JsonProperty("NextStates")
    Collection<TokenStatusData> nextStates;

    @JsonProperty("AppletID")
    String appletID;
    @JsonProperty("KeyInfo")
    String keyInfo;
    @JsonProperty("Policy")
    String policy;
    @JsonProperty("CreateTimestamp")
    Date createTimestamp;
    @JsonProperty("ModifyTimestamp")
    Date modifyTimestamp;

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public TokenStatusData getStatus() {
        return status;
    }

    public void setStatus(TokenStatusData status) {
        this.status = status;
    }

    public Collection<TokenStatusData> getNextStates() {
        return nextStates;
    }

    public void setNextStates(Collection<TokenStatusData> nextStates) {
        this.nextStates = nextStates;
    }

    public String getAppletID() {
        return appletID;
    }

    public void setAppletID(String appletID) {
        this.appletID = appletID;
    }

    public String getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(String keyInfo) {
        this.keyInfo = keyInfo;
    }

    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    public Date getCreateTimestamp() {
        return createTimestamp;
    }

    public void setCreateTimestamp(Date createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    public Date getModifyTimestamp() {
        return modifyTimestamp;
    }

    public void setModifyTimestamp(Date modifyTimestamp) {
        this.modifyTimestamp = modifyTimestamp;
    }

    @Override
    public int hashCode() {
        return Objects.hash(appletID, createTimestamp, id, keyInfo, modifyTimestamp, nextStates, policy, status,
                tokenID, type, userID);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        TokenData other = (TokenData) obj;
        return Objects.equals(appletID, other.appletID) && Objects.equals(createTimestamp, other.createTimestamp)
                && Objects.equals(id, other.id) && Objects.equals(keyInfo, other.keyInfo)
                && Objects.equals(modifyTimestamp, other.modifyTimestamp)
                && Objects.equals(nextStates, other.nextStates) && Objects.equals(policy, other.policy)
                && Objects.equals(status, other.status) && Objects.equals(tokenID, other.tokenID)
                && Objects.equals(type, other.type) && Objects.equals(userID, other.userID);
    }

}
