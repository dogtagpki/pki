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
public class CAInfo extends RESTMessage {

    public static final String ENCRYPT_MECHANISM = "encrypt";
    public static final String KEYWRAP_MECHANISM = "keywrap";
    public static final String RSA_PUBLIC_KEY_WRAP = "RSA";

    String archivalMechanism;
    String encryptAlgorithm;
    String keyWrapAlgorithm;
    String rsaPublicKeyWrapAlgorithm;
    String caRsaPublicKeyWrapAlgorithm;

    @JsonProperty("ArchivalMechanism")
    public String getArchivalMechanism() {
        return archivalMechanism;
    }

    public void setArchivalMechanism(String archivalMechanism) {
        this.archivalMechanism = archivalMechanism;
    }

    @JsonProperty("EncryptionAlgorithm")
    public String getEncryptAlgorithm() {
        return encryptAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        this.encryptAlgorithm = encryptAlgorithm;
    }

    @JsonProperty("KeyWrapAlgorithm")
    public String getKeyWrapAlgorithm() {
        return keyWrapAlgorithm;
    }

    public void setKeyWrapAlgorithm(String keyWrapAlgorithm) {
        this.keyWrapAlgorithm = keyWrapAlgorithm;
    }

    @JsonProperty("RsaPublicKeyWrapAlgorithm")
    public String getRsaPublicKeyWrapAlgorithm() {
        return rsaPublicKeyWrapAlgorithm;
    }

    public void setRsaPublicKeyWrapAlgorithm(String rsaPublicKeyWrapAlgorithm) {
        this.rsaPublicKeyWrapAlgorithm = rsaPublicKeyWrapAlgorithm;
    }

    @JsonProperty("CaRsaPublicKeyWrapAlgorithm")
    public String getCaRsaPublicKeyWrapAlgorithm() {
        return caRsaPublicKeyWrapAlgorithm;
    }

    public void setCaRsaPublicKeyWrapAlgorithm(String caRsaPublicKeyWrapAlgorithm) {
        this.caRsaPublicKeyWrapAlgorithm = caRsaPublicKeyWrapAlgorithm;
    }


    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((archivalMechanism == null) ? 0 : archivalMechanism.hashCode());
        result = prime * result + ((encryptAlgorithm == null) ? 0 : encryptAlgorithm.hashCode());
        result = prime * result + ((keyWrapAlgorithm == null) ? 0 : keyWrapAlgorithm.hashCode());
        result = prime * result + ((rsaPublicKeyWrapAlgorithm == null) ? 0 : rsaPublicKeyWrapAlgorithm.hashCode());
        result = prime * result + ((caRsaPublicKeyWrapAlgorithm == null) ? 0 : caRsaPublicKeyWrapAlgorithm.hashCode());
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
        CAInfo other = (CAInfo) obj;
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
        if (keyWrapAlgorithm == null) {
            if (other.keyWrapAlgorithm != null)
                return false;
        } else if (!keyWrapAlgorithm.equals(other.keyWrapAlgorithm)) {
            return false;
        } else if (!rsaPublicKeyWrapAlgorithm.equals(other.rsaPublicKeyWrapAlgorithm)) {
            return false;
        } else if (!caRsaPublicKeyWrapAlgorithm.equals(other.caRsaPublicKeyWrapAlgorithm)) {
            return false;
        }

        return true;
    }
}

