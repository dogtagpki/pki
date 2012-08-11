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

package com.netscape.certsrv.cert;

import java.io.StringReader;
import java.io.StringWriter;

import javax.ws.rs.FormParam;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="CertUnrevokeRequest")
public class CertUnrevokeRequest {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            JAXBContext context = JAXBContext.newInstance(CertUnrevokeRequest.class);
            marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = context.createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    RequestId requestID;

    @XmlElement(name="requestID")
    @FormParam("requestId")
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((requestID == null) ? 0 : requestID.hashCode());
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
        CertUnrevokeRequest other = (CertUnrevokeRequest) obj;
        if (requestID == null) {
            if (other.requestID != null)
                return false;
        } else if (!requestID.equals(other.requestID))
            return false;
        return true;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static CertUnrevokeRequest valueOf(String string) throws Exception {
        try {
            return (CertUnrevokeRequest)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        CertUnrevokeRequest before = new CertUnrevokeRequest();
        before.setRequestID(new RequestId("42323234"));

        String string = before.toString();
        System.out.println(string);

        CertUnrevokeRequest after = CertUnrevokeRequest.valueOf(string);

        System.out.println(before.equals(after));
    }
}
