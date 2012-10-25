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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.netscape.certsrv.base.Link;
import com.netscape.certsrv.request.RequestStatus;

@XmlRootElement(name = "KeyRequestInfos")
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyRequestInfos {

    @XmlElementRef
    protected Collection<KeyRequestInfo> requests = new ArrayList<KeyRequestInfo>();

    @XmlElement(name = "Link")
    protected List<Link> links = new ArrayList<Link>();

    /**
     * @return the requests
     */
    public Collection<KeyRequestInfo> getRequests() {
        return requests;
    }

    /**
     * @param requests the requests to set
     */
    public void setRequests(Collection<KeyRequestInfo> requests) {
        this.requests.clear();
        if (requests == null) return;
        this.requests.addAll(requests);
    }

    /**
     * @param request the request to add
     */
    public void addRequest(KeyRequestInfo request) {
        requests.add(request);
    }

    /**
     * @return the links
     */
    public List<Link> getLinks() {
        return links;
    }

    /**
     * @param links the links to set
     */
    public void setLinks(List<Link> links) {
        this.links.clear();
        if (links == null) return;
        this.links.addAll(links);
    }

    /**
     * @param links the link to add
     */
    public void addLink(Link link) {
        this.links.add(link);
    }

    @XmlTransient
    public String getNext() {
        for (Link link : links) {
            if ("next".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }

    @XmlTransient
    public String getPrevious() {
        for (Link link : links) {
            if ("previous".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((links == null) ? 0 : links.hashCode());
        result = prime * result + ((requests == null) ? 0 : requests.hashCode());
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
        KeyRequestInfos other = (KeyRequestInfos) obj;
        if (links == null) {
            if (other.links != null)
                return false;
        } else if (!links.equals(other.links))
            return false;
        if (requests == null) {
            if (other.requests != null)
                return false;
        } else if (!requests.equals(other.requests))
            return false;
        return true;
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
        before.addRequest(request);

        String string = before.toString();
        System.out.println(string);

        KeyRequestInfos after = KeyRequestInfos.valueOf(string);
        System.out.println(after);

        System.out.println(before.equals(after));
    }
}
