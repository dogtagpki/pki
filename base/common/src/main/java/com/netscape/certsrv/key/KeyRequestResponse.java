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
// (C) 2014 Red Hat, Inc.
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
import com.netscape.certsrv.request.RequestId;

@XmlRootElement(name = "KeyRequestResponse")
@XmlAccessorType(XmlAccessType.NONE)
public class KeyRequestResponse {

    KeyRequestInfo requestInfo;
    KeyData keyData;

    @XmlElement(name="RequestInfo")
    public KeyRequestInfo getRequestInfo() {
        return requestInfo;
    }

    public void setRequestInfo(KeyRequestInfo requestInfo) {
        this.requestInfo = requestInfo;
    }

    @XmlElement(name="KeyData")
    public KeyData getKeyData() {
        return keyData;
    }

    public void setKeyData(KeyData keyData) {
        this.keyData = keyData;
    }

    public KeyId getKeyId(){
        return this.requestInfo.getKeyId();
    }

    public RequestId getRequestId(){
        return this.requestInfo.getRequestId();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((keyData == null) ? 0 : keyData.hashCode());
        result = prime * result + ((requestInfo == null) ? 0 : requestInfo.hashCode());
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
        KeyRequestResponse other = (KeyRequestResponse) obj;
        if (keyData == null) {
            if (other.keyData != null)
                return false;
        } else if (!keyData.equals(other.keyData))
            return false;
        if (requestInfo == null) {
            if (other.requestInfo != null)
                return false;
        } else if (!requestInfo.equals(other.requestInfo))
            return false;
        return true;
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(KeyRequestResponse.class).createMarshaller();
        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static KeyRequestResponse fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(KeyRequestResponse.class).createUnmarshaller();
        return (KeyRequestResponse) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        mapper.setSerializationInclusion(Include.NON_NULL);
        return mapper.writeValueAsString(this);
    }

    public static KeyRequestResponse fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, KeyRequestResponse.class);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws Exception {

        KeyRequestResponse before = new KeyRequestResponse();

        KeyRequestInfo requestInfo = new KeyRequestInfo();
        requestInfo.setRequestType("test");
        before.setRequestInfo(requestInfo);

        KeyData keyData = new KeyData();
        keyData.setAlgorithm("AES");
        before.setKeyData(keyData);

        String xml = before.toString();
        System.out.println("XML (before): " + xml);

        KeyRequestResponse afterXML = KeyRequestResponse.fromXML(xml);
        System.out.println("XML (after): " + afterXML);

        System.out.println(before.equals(afterXML));

        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        KeyRequestResponse afterJSON = KeyRequestResponse.fromJSON(json);
        System.out.println("JSON (after): " + json);

        System.out.println(before.equals(afterJSON));
    }
}
