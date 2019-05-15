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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.acme;

import java.io.UnsupportedEncodingException;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.apache.commons.codec.binary.Base64;

@XmlRootElement
public class JWS {

    @XmlElement(name="protected")
    private String protectedHeader;

    @XmlElement
    private String payload;

    @XmlElement
    private String signature;

    public String getProtectedHeader() {
        return protectedHeader;
    }

    public String getDecodedProtectedHeader() throws UnsupportedEncodingException {
        return new String(Base64.decodeBase64(protectedHeader), "UTF-8");
    }

    public void setProtectedHeader(String protectedHeader) {
        this.protectedHeader = protectedHeader;
    }

    public String getPayload() {
        return payload;
    }

    public byte[] getDecodedPayload() {
        return Base64.decodeBase64(payload);
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getSignature() {
        return signature;
    }

    public byte[] getDecodedSignature() {
        return Base64.decodeBase64(payload);
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
