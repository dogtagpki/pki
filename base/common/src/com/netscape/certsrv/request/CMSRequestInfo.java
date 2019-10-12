//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.request;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;
import com.netscape.certsrv.key.KeyRequestInfo;

@XmlRootElement(name="CMSRequestInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public  class CMSRequestInfo {

    @XmlElement
    protected String requestType;

    @XmlElement
    @XmlJavaTypeAdapter(RequestStatusAdapter.class)
    protected RequestStatus requestStatus;

    @XmlElement
    protected String requestURL;

    @XmlElement
    protected String realm;

    /**
     * @return the requestType
     */
    public String getRequestType() {
        return requestType;
    }

    /**
     * @param requestType the requestType to set
     */
    public void setRequestType(String requestType) {
        this.requestType = requestType;
    }

    /**
     * @return the requestStatus
     */
    public RequestStatus getRequestStatus() {
        return requestStatus;
    }

    /**
     * @param requestStatus the requestStatus to set
     */
    public void setRequestStatus(RequestStatus requestStatus) {
        this.requestStatus = requestStatus;
    }

    /**
     * @return the requestURL
     */
    public String getRequestURL() {
        return requestURL;
    }

    /**
     * @return the request ID in the requestURL
     */
    public RequestId getRequestId() {
        String id = requestURL.substring(requestURL.lastIndexOf("/") + 1);
        return new RequestId(id);
    }

    /**
     * @param requestURL the requestURL to set
     */
    public void setRequestURL(String requestURL) {
        this.requestURL = requestURL;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((realm == null) ? 0 : realm.hashCode());
        result = prime * result + ((requestStatus == null) ? 0 : requestStatus.hashCode());
        result = prime * result + ((requestType == null) ? 0 : requestType.hashCode());
        result = prime * result + ((requestURL == null) ? 0 : requestURL.hashCode());
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
        CMSRequestInfo other = (CMSRequestInfo) obj;
        if (realm == null) {
            if (other.realm != null)
                return false;
        } else if (!realm.equals(other.realm))
            return false;
        if (requestStatus == null) {
            if (other.requestStatus != null)
                return false;
        } else if (!requestStatus.equals(other.requestStatus))
            return false;
        if (requestType == null) {
            if (other.requestType != null)
                return false;
        } else if (!requestType.equals(other.requestType))
            return false;
        if (requestURL == null) {
            if (other.requestURL != null)
                return false;
        } else if (!requestURL.equals(other.requestURL))
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

    public static CMSRequestInfo fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(CMSRequestInfo.class).createUnmarshaller();
        return (CMSRequestInfo)unmarshaller.unmarshal(new StringReader(string));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        mapper.setSerializationInclusion(Include.NON_NULL);
        return mapper.writeValueAsString(this);
    }

    public static CMSRequestInfo fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setAnnotationIntrospector(new JaxbAnnotationIntrospector(mapper.getTypeFactory()));
        return mapper.readValue(json, CMSRequestInfo.class);
    }

    public String toString() {
        try {
            return toXML();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String args[]) throws Exception {

        CMSRequestInfo before = new CMSRequestInfo();
        before.setRequestType("securityDataEnrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);

        String xml = before.toString();
        System.out.println("XML (before): " + xml);

        CMSRequestInfo afterXML = CMSRequestInfo.fromXML(xml);
        System.out.println("XML (after): " + afterXML.toXML());

        System.out.println(before.equals(afterXML));

        String json = before.toJSON();
        System.out.println("JSON (before): " + json);

        CMSRequestInfo afterJSON = CMSRequestInfo.fromJSON(json);
        System.out.println("JSON (after): " + afterJSON.toJSON());

        System.out.println(before.equals(afterJSON));
    }
}
