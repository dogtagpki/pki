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

/**
 *
 */
package com.netscape.certsrv.key;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name="KeyData")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyData {
    @XmlElement
    String wrappedPrivateData;

    @XmlElement
    String nonceData;

    @XmlElement
    String p12Data;

    public KeyData() {
        // required for JAXB (defaults)
    }

    /**
     * @return the wrappedPrivateData
     */
    public String getWrappedPrivateData() {
        return wrappedPrivateData;
    }

    /**
     * @param wrappedPrivateData the wrappedPrivateData to set
     */
    public void setWrappedPrivateData(String wrappedPrivateData) {
        this.wrappedPrivateData = wrappedPrivateData;
    }

    /**
     * @return the nonceData
     */

    public String getNonceData() {
        return nonceData;
    }

    /**
     * @param nonceData the nonceData to set
     */

    public void setNonceData(String nonceData) {
        this.nonceData = nonceData;
    }

    /**
     * @return the p12Data
     */
    public String getP12Data() {
        return p12Data;
    }

    /**
     * @param p12Data the p12Data to set
     */
    public void setP12Data(String p12Data) {
        this.p12Data = p12Data;
    }
}
