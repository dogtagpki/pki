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

package com.netscape.cms.servlet.request.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.dbs.certdb.CertId;

@XmlRootElement(name = "CertRequestInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertRequestInfo extends CMSRequestInfo {

    @XmlElement
    protected String certURL;

    @XmlElement
    protected String certRequestType;

    public CertRequestInfo() {
        // required to be here for JAXB (defaults)
    }

    /**
     * @param certRequestType to set
     */

    public void setCertRequestType(String certRequestType) {
        this.certRequestType = certRequestType;
    }

    /**
     * @return the certRequestType
     */

    public String getCertRequestType() {
        return certRequestType;
    }

    /**
     * @set the certURL
     */
    public void setCertURL(String certURL) {
        this.certURL = certURL;
    }

    /**
     * @return the certURL
     */
    public String getCertURL() {
        return certURL;
    }

    /**
     * @return the certId
     */

    public CertId getCertId() {
        String id = certURL.substring(certURL.lastIndexOf("/") + 1);
        return new CertId(id);
    }

}
