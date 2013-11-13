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

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.base.DataCollection;
//import com.netscape.certsrv.base.Link;

@XmlRootElement(name = "ProfileDataInfos")
public class ProfileDataInfos extends DataCollection<ProfileDataInfo> {

    @XmlElementRef
    public Collection<ProfileDataInfo> getEntries() {
        return super.getEntries();
    }

    @XmlTransient
    public String getNext() {
        for (Link link : getLinks()) {
            if ("next".equals(link. getRel())) {
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
}
