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
import com.netscape.certsrv.base.RESTMessage;

/**
 * @author Ade Lee
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class CAInfo extends RESTMessage {

    public static final String ENCRYPT_MECHANISM = "encrypt";
    public static final String KEYWRAP_MECHANISM = "keywrap";

    String archivalMechanism;
    String encryptAlgorithm;
    String keyWrapAlgorithm;

    public String getArchivalMechanism() {
        return archivalMechanism;
    }

    public void setArchivalMechanism(String archivalMechanism) {
        this.archivalMechanism = archivalMechanism;
    }

    public String getEncryptAlgorithm() {
        return encryptAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        this.encryptAlgorithm = encryptAlgorithm;
    }

    public String getKeyWrapAlgorithm() {
        return keyWrapAlgorithm;
    }

    public void setKeyWrapAlgorithm(String keyWrapAlgorithm) {
        this.keyWrapAlgorithm = keyWrapAlgorithm;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((archivalMechanism == null) ? 0 : archivalMechanism.hashCode());
        result = prime * result + ((encryptAlgorithm == null) ? 0 : encryptAlgorithm.hashCode());
        result = prime * result + ((keyWrapAlgorithm == null) ? 0 : keyWrapAlgorithm.hashCode());
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
        } else if (!keyWrapAlgorithm.equals(other.keyWrapAlgorithm))
            return false;
        return true;
    }

}

