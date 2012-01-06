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
package com.netscape.cms.servlet.cert.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;

/**
 * @author alee
 * 
 */
@XmlRootElement(name = "CertificateData")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateData {
    @XmlElement
    private String b64;

    public CertificateData() {
        // required for jaxb
    }

    /**
     * @return the b64
     */
    public String getB64() {
        return b64;
    }

    /**
     * @param b64 the b64 to set
     */
    public void setB64(String b64) {
        this.b64 = b64;
    }

}
