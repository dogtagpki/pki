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

package com.netscape.certsrv.logging;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="AuditLogFindRequest")
@XmlAccessorType(XmlAccessType.NONE)
public class AuditLogFindRequest {

    String fileName;

    @XmlElement(name="FileName")
    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((fileName == null) ? 0 : fileName.hashCode());
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
        AuditLogFindRequest other = (AuditLogFindRequest) obj;
        if (fileName == null) {
            if (other.fileName != null)
                return false;
        } else if (!fileName.equals(other.fileName))
            return false;
        return true;
    }

    public String toString() {
        try {
            Marshaller marshaller = JAXBContext.newInstance(AuditLogFindRequest.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

            StringWriter sw = new StringWriter();
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static AuditLogFindRequest valueOf(String string) throws Exception {
        Unmarshaller unmarshaller = JAXBContext.newInstance(AuditLogFindRequest.class).createUnmarshaller();
        return (AuditLogFindRequest)unmarshaller.unmarshal(new StringReader(string));
    }

    public static void main(String args[]) throws Exception {

        AuditLogFindRequest before = new AuditLogFindRequest();
        before.setFileName("audit.log");

        String string = before.toString();
        System.out.println(string);

        AuditLogFindRequest after = AuditLogFindRequest.valueOf(string);
        System.out.println(before.equals(after));
    }
}
