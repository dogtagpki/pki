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
package com.netscape.cms.servlet.cert.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.dbs.certdb.CertId;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertDataInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertDataInfo {

    @XmlElement
    protected String certURL;

    public CertDataInfo() {
        // required for JAXB (defaults)
    }

    /**
     * @return the CertURL
     */
    public String getCertURL() {
        return certURL;
    }

    /**
     * @param CertURL the certURL to set
     */
    public void setCertURL(String certURL) {
        this.certURL = certURL;
    }

    /**
     * @return the Cert ID in the CertURL
     */
    public CertId getCertId() {
        String id = certURL.substring(certURL.lastIndexOf("/") + 1);
        return new CertId(id);
    }

}
