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
package com.netscape.certsrv.cert;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.CertIdAdapter;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "CertRetrievalRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class CertRetrievalRequest {

    private static final String CERT_ID = "certId";

    @XmlElement
    @XmlJavaTypeAdapter(CertIdAdapter.class)
    protected CertId certId;

    @XmlElement
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    protected RequestId requestId;

    public CertRetrievalRequest() {
        // required for JAXB (defaults)
    }

    public CertRetrievalRequest(MultivaluedMap<String, String> form) {
        if (form.containsKey(CERT_ID)) {
            certId = new CertId(form.getFirst(CERT_ID));
        }
    }

    /**
     * @return the CertId
     */
    public CertId getCertId() {
        return certId;
    }

    /**
     * @param CertId the CertId to set
     */
    public void setCertId(CertId certId) {
        this.certId = certId;
    }

}
