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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author alee
 *
 */
@XmlRootElement(name="ConfigurationResponse")
@XmlAccessorType(XmlAccessType.FIELD)
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CertificateSetupResponse {

    @XmlElement
    protected List<SystemCertData> systemCerts;

    public CertificateSetupResponse() {
        systemCerts = new ArrayList<>();
    }

    /**
     * @return the systemCerts
     */
    public List<SystemCertData> getSystemCerts() {
        return systemCerts;
    }

    /**
     * @param systemCerts the systemCerts to set
     */
    public void setSystemCerts(List<SystemCertData> systemCerts) {
        this.systemCerts = systemCerts;
    }

    @Override
    public int hashCode() {
        return Objects.hash(systemCerts);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertificateSetupResponse other = (CertificateSetupResponse) obj;
        return Objects.equals(systemCerts, other.systemCerts);
    }

    public String toXML() throws Exception {
        Marshaller marshaller = JAXBContext.newInstance(CertificateSetupResponse.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter sw = new StringWriter();
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static CertificateSetupResponse fromXML(String xml) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(CertificateSetupResponse.class).createUnmarshaller();
        return (CertificateSetupResponse) unmarshaller.unmarshal(new StringReader(xml));
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static CertificateSetupResponse fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, CertificateSetupResponse.class);
    }

}
