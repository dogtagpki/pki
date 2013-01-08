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
import java.util.Date;

import javax.ws.rs.FormParam;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevocationReasonAdapter;

import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestIdAdapter;
import com.netscape.certsrv.util.DateAdapter;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="CertRevokeRequest")
public class CertRevokeRequest {

    public static Marshaller marshaller;
    public static Unmarshaller unmarshaller;

    static {
        try {
            JAXBContext context = JAXBContext.newInstance(CertRevokeRequest.class);
            marshaller = context.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            unmarshaller = context.createUnmarshaller();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    RequestId requestID;
    RevocationReason reason;
    Date invalidityDate;
    String comments;
    String encoded;
    Long nonce;


    @XmlElement(name="RequestID")
    @FormParam("requestId")
    @XmlJavaTypeAdapter(RequestIdAdapter.class)
    public RequestId getRequestID() {
        return requestID;
    }

    public void setRequestID(RequestId requestID) {
        this.requestID = requestID;
    }

    @XmlElement(name="Reason")
    @FormParam("revocationReason")
    @XmlJavaTypeAdapter(RevocationReasonAdapter.class)
    public RevocationReason getReason() {
        return reason;
    }

    public void setReason(RevocationReason reason) {
        this.reason = reason;
    }

    @XmlElement(name="InvalidityDate")
    @FormParam("invalidityDate")
    @XmlJavaTypeAdapter(DateAdapter.class)
    public Date getInvalidityDate() {
        return invalidityDate;
    }

    public void setInvalidityDate(Date invalidityDate) {
        this.invalidityDate = invalidityDate;
    }

    @XmlElement(name="Comments")
    @FormParam(IRequest.REQUESTOR_COMMENTS)
    public String getComments() {
        return comments;
    }

    public void setComments(String comments) {
        this.comments = comments;
    }

    @XmlElement(name="Encoded")
    @FormParam("b64eCertificate")
    public String getEncoded() {
        return encoded;
    }

    public void setEncoded(String encoded) {
        this.encoded = encoded;
    }

    @XmlElement(name="Nonce")
    @FormParam("nonce")
    public Long getNonce() {
        return nonce;
    }

    public void setNonce(Long nonce) {
        this.nonce = nonce;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((comments == null) ? 0 : comments.hashCode());
        result = prime * result + ((encoded == null) ? 0 : encoded.hashCode());
        result = prime * result + ((invalidityDate == null) ? 0 : invalidityDate.hashCode());
        result = prime * result + ((nonce == null) ? 0 : nonce.hashCode());
        result = prime * result + ((reason == null) ? 0 : reason.hashCode());
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
        CertRevokeRequest other = (CertRevokeRequest) obj;
        if (comments == null) {
            if (other.comments != null)
                return false;
        } else if (!comments.equals(other.comments))
            return false;
        if (encoded == null) {
            if (other.encoded != null)
                return false;
        } else if (!encoded.equals(other.encoded))
            return false;
        if (invalidityDate == null) {
            if (other.invalidityDate != null)
                return false;
        } else if (!invalidityDate.equals(other.invalidityDate))
            return false;
        if (nonce == null) {
            if (other.nonce != null)
                return false;
        } else if (!nonce.equals(other.nonce))
            return false;
        if (reason == null) {
            if (other.reason != null)
                return false;
        } else if (!reason.equals(other.reason))
            return false;
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

    public static CertRevokeRequest valueOf(String string) throws Exception {
        try {
            return (CertRevokeRequest)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        CertRevokeRequest before = new CertRevokeRequest();
        before.setRequestID(new RequestId("42323234"));
        before.setReason(RevocationReason.CERTIFICATE_HOLD);
        before.setInvalidityDate(new Date());
        before.setComments("test");
        before.setEncoded("test");
        before.setNonce(12345l);

        String string = before.toString();
        System.out.println(string);

        CertRevokeRequest after = CertRevokeRequest.valueOf(string);

        System.out.println(before.equals(after));
    }
}
