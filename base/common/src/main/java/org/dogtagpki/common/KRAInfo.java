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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.common;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author Ade Lee
 */
@XmlRootElement(name="KRAInfo")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KRAInfo extends ResourceMessage {

    String archivalMechanism;
    String recoveryMechanism;
    String encryptAlgorithm;
    String wrapAlgorithm;

    @XmlElement(name="ArchivalMechanism")
    public String getArchivalMechanism() {
        return archivalMechanism;
    }

    public void setArchivalMechanism(String archivalMechanism) {
        this.archivalMechanism = archivalMechanism;
    }

    @XmlElement(name="RecoveryMechanism")
    public String getRecoveryMechanism() {
        return recoveryMechanism;
    }

    public void setRecoveryMechanism(String recoveryMechanism) {
        this.recoveryMechanism = recoveryMechanism;
    }

    @XmlElement(name="EncryptAlgorithm")
    public String getEncryptAlgorithm() {
        return encryptAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        this.encryptAlgorithm = encryptAlgorithm;
    }

    @XmlElement(name="WrapAlgorithm")
    public String getWrapAlgorithm() {
        return wrapAlgorithm;
    }

    public void setWrapAlgorithm(String wrapAlgorithm) {
        this.wrapAlgorithm = wrapAlgorithm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((archivalMechanism == null) ? 0 : archivalMechanism.hashCode());
        result = prime * result + ((encryptAlgorithm == null) ? 0 : encryptAlgorithm.hashCode());
        result = prime * result + ((recoveryMechanism == null) ? 0 : recoveryMechanism.hashCode());
        result = prime * result + ((wrapAlgorithm == null) ? 0 : wrapAlgorithm.hashCode());
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
        KRAInfo other = (KRAInfo) obj;
        if (archivalMechanism == null) {
            if (other.archivalMechanism != null)
                return false;
        } else if (!archivalMechanism.equals(other.archivalMechanism))
            return false;
        if (encryptAlgorithm == null) {
            if (other.encryptAlgorithm != null)
                return false;
        } else if (!encryptAlgorithm.equals(other.encryptAlgorithm))
            return false;
        if (recoveryMechanism == null) {
            if (other.recoveryMechanism != null)
                return false;
        } else if (!recoveryMechanism.equals(other.recoveryMechanism))
            return false;
        if (wrapAlgorithm == null) {
            if (other.wrapAlgorithm != null)
                return false;
        } else if (!wrapAlgorithm.equals(other.wrapAlgorithm))
            return false;
        return true;
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static KRAInfo fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, KRAInfo.class);
    }

    public String toXML() throws Exception {
        StringWriter sw = new StringWriter();
        Marshaller marshaller = JAXBContext.newInstance(KRAInfo.class).createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
        marshaller.marshal(this, sw);
        return sw.toString();
    }

    public static KRAInfo fromXML(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(KRAInfo.class).createUnmarshaller();
        return (KRAInfo)unmarshaller.unmarshal(new StringReader(string));
    }

}

