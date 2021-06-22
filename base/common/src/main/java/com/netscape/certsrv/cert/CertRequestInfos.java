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
package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.base.Link;

@XmlRootElement(name = "CertRequestInfos")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertRequestInfos extends DataCollection<CertRequestInfo> {

    @Override
    @XmlElementRef
    public Collection<CertRequestInfo> getEntries() {
        return super.getEntries();
    }

    @XmlTransient
    public String getNext() {
        for (Link link : getLinks()) {
            if ("next".equals(link.getRelationship())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    @XmlTransient
    public String getPrevious() {
        for (Link link : getLinks()) {
            if ("previous".equals(link.getRelationship())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // required to access private RequestStatus.label
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
        return mapper.writeValueAsString(this);
    }

    public static CertRequestInfos fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        // required to access private RequestStatus.label
        mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
        return mapper.readValue(json, CertRequestInfos.class);
    }

    public String toXML() throws Exception {
        StringWriter sw = new StringWriter();
        Marshaller marshaller = JAXBContext.newInstance(CertRequestInfos.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static CertRequestInfos fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(CertRequestInfos.class).createUnmarshaller();
        return (CertRequestInfos)unmarshaller.unmarshal(new StringReader(string));
    }

}
