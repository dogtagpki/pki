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
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

import java.util.Collection;
import java.util.List;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import com.netscape.certsrv.base.Link;

@XmlRootElement(name = "ProfileDataInfos")
public class ProfileDataInfos {

    protected Collection<ProfileDataInfo> profileInfos;
    protected List<Link> links;

    /**
     * @return the ProfileInfos
     */
    @XmlElementRef
    public Collection<ProfileDataInfo> getProfileInfos() {
        return profileInfos;
    }

    /**
     * @param ProfileInfos theProfileInfos to set
     */
    public void setProfileInfos(Collection<ProfileDataInfo> profileInfos) {
        this.profileInfos = profileInfos;
    }

    /**
     * @return the links
     */
    @XmlElementRef
    public List<Link> getLinks() {
        return links;
    }

    /**
     * @param links the links to set
     */
    public void setLinks(List<Link> links) {
        this.links = links;
    }

    @XmlTransient
    public String getNext() {
        if (links == null) {
            return null;
        }
        for (Link link : links) {
            if ("next".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }

    @XmlTransient
    public String getPrevious() {
        if (links == null) {
            return null;
        }
        for (Link link : links) {
            if ("previous".equals(link.getRelationship())) {
                return link.getHref();
            }
        }
        return null;
    }
}
