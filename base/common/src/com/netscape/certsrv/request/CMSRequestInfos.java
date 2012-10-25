//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2011 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.request;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.netscape.certsrv.base.Link;

//Convenience class to simply hold a Collection of CMSRequests and a List of Links.
public class CMSRequestInfos {

    protected Collection<CMSRequestInfo> requests = new ArrayList<CMSRequestInfo>();
    protected List<Link> links = new ArrayList<Link>();

    /**
     * @return the requests
     */
    public Collection<CMSRequestInfo> getRequests() {
        return requests;
    }

    /**
     * @param requests the requests to set
     */
    public void setRequests(Collection<CMSRequestInfo> requests) {
        this.requests.clear();
        if (requests == null) return;
        this.requests.addAll(requests);
    }

    /**
     * @param requests the requests to add
     */
    public void addRequest(CMSRequestInfo request) {
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
        links.add(link);
    }
}
