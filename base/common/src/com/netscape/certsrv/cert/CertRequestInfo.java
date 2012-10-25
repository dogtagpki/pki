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

package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.CMSRequestInfo;
import com.netscape.certsrv.request.RequestStatus;

@XmlRootElement(name = "CertRequestInfo")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertRequestInfo extends CMSRequestInfo {

    public static final String REQ_COMPLETE = "complete";

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
        if (certURL == null) return null;
        String id = certURL.substring(certURL.lastIndexOf("/") + 1);
        return new CertId(id);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certRequestType == null) ? 0 : certRequestType.hashCode());
        result = prime * result + ((certURL == null) ? 0 : certURL.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CertRequestInfo other = (CertRequestInfo) obj;
        if (certRequestType == null) {
            if (other.certRequestType != null)
                return false;
        } else if (!certRequestType.equals(other.certRequestType))
            return false;
        if (certURL == null) {
            if (other.certURL != null)
                return false;
        } else if (!certURL.equals(other.certURL))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            Marshaller marshaller = JAXBContext.newInstance(CertRequestInfo.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static CertRequestInfo valueOf(String string) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(CertRequestInfo.class).createUnmarshaller();
            return (CertRequestInfo)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        CertRequestInfo before = new CertRequestInfo();
        before.setRequestType("enrollment");
        before.setRequestStatus(RequestStatus.COMPLETE);
        before.setCertRequestType("pkcs10");

        String string = before.toString();
        System.out.println(string);

        CertRequestInfo after = CertRequestInfo.valueOf(string);
        System.out.println(after);

        System.out.println(before.equals(after));
    }
}
