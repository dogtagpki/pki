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
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.jboss.resteasy.plugins.providers.atom.Link;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Token")
public class TokenData {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(TokenData.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(TokenData.class).createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    String id;
    String userID;
    String status;
    String reason;
    String appletID;
    String keyInfo;
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

    @XmlElement(name="UserID")
    public String getUserID() {
        return userID;
    }

    public void setUserID(String userID) {
        this.userID = userID;
    }

    @XmlElement(name="Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @XmlElement(name="Reason")
    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
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
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        result = prime * result + ((link == null) ? 0 : link.hashCode());
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
        TokenData other = (TokenData) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        if (link == null) {
            if (other.link != null)
                return false;
        } else if (!link.equals(other.link))
            return false;
        if (userID == null) {
            if (other.userID != null)
                return false;
        } else if (!userID.equals(other.userID))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static TokenData valueOf(String string) throws Exception {
        try {
            return (TokenData)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        TokenData before = new TokenData();
        before.setID("token1");
        before.setUserID("user1");
        before.setStatus("revoked");
        before.setReason("lost");
        before.setAppletID("APPLET1234");
        before.setKeyInfo("key info");
        before.setCreateTimestamp(new Date());
        before.setModifyTimestamp(new Date());

        String string = before.toString();
        System.out.println(string);

        TokenData after = TokenData.valueOf(string);
        System.out.println(before.equals(after));
    }
}
