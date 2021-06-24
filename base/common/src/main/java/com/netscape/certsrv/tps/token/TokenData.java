
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

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;
import java.util.Date;
import java.util.Objects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Token")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class TokenData {

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
    String tokenID;
    String userID;
    String type;

    TokenStatusData status;
    Collection<TokenStatusData> nextStates;

    String appletID;
    String keyInfo;
    String policy;
    Date createTimestamp;
    Date modifyTimestamp;

    Link link;

    @XmlAttribute(name="id")
    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @XmlElement(name="TokenID")
    public String getTokenID() {
        return tokenID;
    }

    public void setTokenID(String tokenID) {
        this.tokenID = tokenID;
    }

    @XmlElement(name="UserID")
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    @XmlElement(name="Type")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @XmlElement(name="Status")
    public TokenStatusData getStatus() {
        return status;
    }

    public void setStatus(TokenStatusData status) {
        this.status = status;
    }

    @XmlElement(name="NextStates")
    public Collection<TokenStatusData> getNextStates() {
        return nextStates;
    }

    public void setNextStates(Collection<TokenStatusData> nextStates) {
        this.nextStates = nextStates;
    }

    @XmlElement(name="AppletID")
    public String getAppletID() {
        return appletID;
    }

    public void setAppletID(String appletID) {
        this.appletID = appletID;
    }

    @XmlElement(name="KeyInfo")
    public String getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(String keyInfo) {
        this.keyInfo = keyInfo;
    }

    @XmlElement(name="Policy")
    public String getPolicy() {
        return policy;
    }

    public void setPolicy(String policy) {
        this.policy = policy;
    }

    @XmlElement(name="CreateTimestamp")
    public Date getCreateTimestamp() {
        return createTimestamp;
    }

    public void setCreateTimestamp(Date createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    @XmlElement(name="ModifyTimestamp")
    public Date getModifyTimestamp() {
        return modifyTimestamp;
    }

    public void setModifyTimestamp(Date modifyTimestamp) {
        this.modifyTimestamp = modifyTimestamp;
    }

    @XmlElement(name="Link")
    public Link getLink() {
        return link;
    }

    public void setLink(Link link) {
        this.link = link;
    }



    @Override
    public int hashCode() {
        return Objects.hash(appletID, createTimestamp, id, keyInfo, link, modifyTimestamp, nextStates, policy, status,
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
                && Objects.equals(link, other.link) && Objects.equals(modifyTimestamp, other.modifyTimestamp)
                && Objects.equals(nextStates, other.nextStates) && Objects.equals(policy, other.policy)
                && Objects.equals(status, other.status) && Objects.equals(tokenID, other.tokenID)
                && Objects.equals(type, other.type) && Objects.equals(userID, other.userID);
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(TokenData.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static TokenData fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(TokenData.class).createUnmarshaller();
        return (TokenData) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static TokenData fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, TokenData.class);
    }

}
