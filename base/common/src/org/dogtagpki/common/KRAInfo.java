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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.ResourceMessage;

/**
 * @author Ade Lee
 */
@XmlRootElement(name="KRAInfo")
public class KRAInfo extends ResourceMessage {

    private static Logger logger = LoggerFactory.getLogger(Info.class);

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            marshaller = JAXBContext.newInstance(KRAInfo.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = JAXBContext.newInstance(KRAInfo.class).createUnmarshaller();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
    }

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

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KRAInfo valueOf(String string) throws Exception {
        return (KRAInfo)unmarshaller.unmarshal(new StringReader(string));
    }

    public static void main(String args[]) throws Exception {

        KRAInfo before = new KRAInfo();
        before.setArchivalMechanism("encrypt");
        before.setRecoveryMechanism("keywrap");
        before.setEncryptAlgorithm("AES/CBC/Pad");
        before.setWrapAlgorithm("AES KeyWrap/Padding");

        String string = before.toString();
        System.out.println(string);

        KRAInfo after = KRAInfo.valueOf(string);
        System.out.println(before.equals(after));
    }
}

