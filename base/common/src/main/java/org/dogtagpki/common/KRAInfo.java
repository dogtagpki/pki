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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.netscape.certsrv.base.RESTMessage;

/**
 * @author Ade Lee
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class KRAInfo extends RESTMessage {

    String archivalMechanism;
    String recoveryMechanism;
    String encryptAlgorithm;
    String wrapAlgorithm;
    String rsaPublicKeyWrapAlgorithm;

    @JsonProperty("ArchivalMechanism")
    public String getArchivalMechanism() {
        return archivalMechanism;
    }

    public void setArchivalMechanism(String archivalMechanism) {
        this.archivalMechanism = archivalMechanism;
    }

    @JsonProperty("RecoveryMechanism")
    public String getRecoveryMechanism() {
        return recoveryMechanism;
    }

    public void setRecoveryMechanism(String recoveryMechanism) {
        this.recoveryMechanism = recoveryMechanism;
    }

   @JsonProperty("EncryptionAlgorithm")
    public String getEncryptAlgorithm() {
        return encryptAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        this.encryptAlgorithm = encryptAlgorithm;
    }

    @JsonProperty("WrapAlgorithm")
    public String getWrapAlgorithm() {
        return wrapAlgorithm;
    }

    public void setWrapAlgorithm(String wrapAlgorithm) {
        this.wrapAlgorithm = wrapAlgorithm;
    }

    @JsonProperty("RsaPublicKeyWrapAlgorithm")
    public String getRsaPublicKeyWrapAlgorithm() {
        return rsaPublicKeyWrapAlgorithm;
    }

    public void setRsaPublicKeyWrapAlgorithm(String rsaPublicKeyWrapAlgorithm) {
        this.rsaPublicKeyWrapAlgorithm = rsaPublicKeyWrapAlgorithm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((archivalMechanism == null) ? 0 : archivalMechanism.hashCode());
        result = prime * result + ((encryptAlgorithm == null) ? 0 : encryptAlgorithm.hashCode());
        result = prime * result + ((recoveryMechanism == null) ? 0 : recoveryMechanism.hashCode());
        result = prime * result + ((wrapAlgorithm == null) ? 0 : wrapAlgorithm.hashCode());
        result = prime * result + ((rsaPublicKeyWrapAlgorithm == null) ? 0 : rsaPublicKeyWrapAlgorithm.hashCode());
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
        } else if (!wrapAlgorithm.equals(other.wrapAlgorithm)) {
            return false;
        } else if (!rsaPublicKeyWrapAlgorithm.equals(other.rsaPublicKeyWrapAlgorithm))
            return false;
        return true;
    }

    public Element toDOM(Document document) {

        Element infoElement = document.createElement("KRAInfo");

        toDOM(document, infoElement);

        if (archivalMechanism != null) {
            Element archivalElement = document.createElement("ArchivalMechanism");
            archivalElement.appendChild(document.createTextNode(archivalMechanism));
            infoElement.appendChild(archivalElement);
        }

        if (recoveryMechanism != null) {
            Element recoveryElement = document.createElement("RecoveryMechanism");
            recoveryElement.appendChild(document.createTextNode(recoveryMechanism));
            infoElement.appendChild(recoveryElement);
        }

        if (encryptAlgorithm != null) {
            Element encryptElement = document.createElement("EncryptionAlgorithm");
            encryptElement.appendChild(document.createTextNode(encryptAlgorithm));
            infoElement.appendChild(encryptElement);
        }

        if (wrapAlgorithm != null) {
            Element wrapElement = document.createElement("WrapAlgorithm");
            wrapElement.appendChild(document.createTextNode(wrapAlgorithm));
            infoElement.appendChild(wrapElement);
        }

        if (rsaPublicKeyWrapAlgorithm != null) {
            Element rsaPublicWrapElement = document.createElement("RsaPublicKeyWrapAlgorithm");
            rsaPublicWrapElement.appendChild(document.createTextNode(rsaPublicKeyWrapAlgorithm));
            infoElement.appendChild(rsaPublicWrapElement);
        }

        return infoElement;
    }

    public static KRAInfo fromDOM(Element infoElement) {

        KRAInfo info = new KRAInfo();

        fromDOM(infoElement, info);

        NodeList archivalList = infoElement.getElementsByTagName("ArchivalMechanism");
        if (archivalList.getLength() > 0) {
            String value = archivalList.item(0).getTextContent();
            info.setArchivalMechanism(value);
        }

        NodeList recoveryList = infoElement.getElementsByTagName("RecoveryMechanism");
        if (recoveryList.getLength() > 0) {
            String value = recoveryList.item(0).getTextContent();
            info.setRecoveryMechanism(value);
        }

        NodeList encryptionList = infoElement.getElementsByTagName("EncryptionAlgorithm");
        if (encryptionList.getLength() > 0) {
            String value = encryptionList.item(0).getTextContent();
            info.setEncryptAlgorithm(value);
        }

        NodeList wrapList = infoElement.getElementsByTagName("WrapAlgorithm");
        if (wrapList.getLength() > 0) {
            String value = wrapList.item(0).getTextContent();
            info.setWrapAlgorithm(value);
        }

        NodeList rsaPublicKeyWrapList = infoElement.getElementsByTagName("RsaPublicKeyWrapAlgorithm");
        if (rsaPublicKeyWrapList.getLength() > 0) {
            String value = rsaPublicKeyWrapList.item(0).getTextContent();
            info.setRsaPublicKeyWrapAlgorithm(value);
        }

        return info;
    }
}

