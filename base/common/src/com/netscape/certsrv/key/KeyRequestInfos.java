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
package com.netscape.certsrv.key;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.base.DataCollection;
import com.netscape.certsrv.request.RequestStatus;

@XmlRootElement(name = "KeyRequestInfos")
public class KeyRequestInfos extends DataCollection<KeyRequestInfo> {

    @XmlElementRef
    public Collection<KeyRequestInfo> getEntries() {
        return super.getEntries();
    }
    @XmlTransient
    public String getNext() {
        for (Link link : getLinks()) {
            if ("next".equals(link.getRel())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    @XmlTransient
    public String getPrevious() {
        for (Link link : getLinks()) {
            if ("previous".equals(link.getRel())) {
                return link.getHref().toString();
            }
        }
        return null;
    }

    public String toString() {
        try {
            StringWriter sw = new StringWriter();
            Marshaller marshaller = JAXBContext.newInstance(KeyRequestInfos.class).createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(this, sw);
            return sw.toString();

        } catch (Exception e) {
            return super.toString();
        }
    }

    public static KeyRequestInfos valueOf(String string) throws Exception {
        try {
            Unmarshaller unmarshaller = JAXBContext.newInstance(KeyRequestInfos.class).createUnmarshaller();
            return (KeyRequestInfos)unmarshaller.unmarshal(new StringReader(string));
        } catch (Exception e) {
            return null;
        }
    }

    public static void main(String args[]) throws Exception {

        KeyRequestInfos before = new KeyRequestInfos();

        KeyRequestInfo request = new KeyRequestInfo();
        request.setRequestType("securityDataEnrollment");
        request.setRequestStatus(RequestStatus.COMPLETE);
        before.addEntry(request);

        String string = before.toString();
        System.out.println(string);

        KeyRequestInfos after = KeyRequestInfos.valueOf(string);
        System.out.println(after);

        System.out.println(before.equals(after));
    }
}
