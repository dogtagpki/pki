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

package com.netscape.certsrv.key;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.RequestStatus;

@XmlRootElement(name = "KeyRequestInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRequestInfo extends CMSRequestInfo {

    @XmlElement
    protected String keyURL;

    public KeyRequestInfo() {
        // required to be here for JAXB (defaults)
    }

    /**
     * @return the keyURL
     */
    public String getKeyURL() {
        return keyURL;
    }

    /**
     * @return the key ID in the keyURL
     */
    public KeyId getKeyId() {
        if (keyURL == null) return null;
        String id = keyURL.substring(keyURL.lastIndexOf("/") + 1);
        return new KeyId(id);
    }

    /**
     * @param keyURL the keyURL to set
     */
    public void setKeyURL(String keyURL) {
        this.keyURL = keyURL;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((keyURL == null) ? 0 : keyURL.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        KeyRequestInfo other = (KeyRequestInfo) obj;
        if (keyURL == null) {
            if (other.keyURL != null)
                return false;
        } else if (!keyURL.equals(other.keyURL))
            return false;
        return true;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(KeyRequestInfo.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static KeyRequestInfo fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(KeyRequestInfo.class).createUnmarshaller();
        return (KeyRequestInfo)unmarshaller.unmarshal(new StringReader(string));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        mapper.setSerializationInclusion(Include.NON_NULL);
        return mapper.writeValueAsString(this);
    }

    public static KeyRequestInfo fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, KeyRequestInfo.class);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws Exception {

        KeyRequestInfo before = new KeyRequestInfo();
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setKeyURL("https://localhost:8443/kra/rest/agent/keys/123");

        String xml = before.toString();
        System.out.println("XML (before): " + xml);

        KeyRequestInfo afterXML = KeyRequestInfo.fromXML(xml);
        System.out.println("XML (before): " + afterXML.toXML());

        System.out.println(before.equals(afterXML));

        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestInfo afterJSON = KeyRequestInfo.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        System.out.println(before.equals(afterJSON));
    }
}
