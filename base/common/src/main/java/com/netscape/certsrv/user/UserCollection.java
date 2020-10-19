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

package com.netscape.certsrv.user;

import java.util.Collection;

import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netscape.certsrv.base.DataCollection;


/**
 * @author Endi S. Dewata
 */
@XmlRootElement(name="Users")
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class UserCollection extends DataCollection<UserData> {

    @XmlElementRef
    public Collection<UserData> getEntries() {
        return super.getEntries();
    }

    public String toJSON() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(this);
    }

    public static UserCollection fromJSON(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, UserCollection.class);
    }

    public static void main(String args[]) throws Exception {

        UserData user = new UserData();
        user.setUserID("testuser");
        user.setFullName("Test User");
        user.setEmail("testuser@example.com");

        UserCollection before = new UserCollection();
        before.addEntry(user);
        before.setTotal(1);

        String json = before.toJSON();
        System.out.println("Before: " + json);

        UserCollection afterJSON = UserCollection.fromJSON(json);
        System.out.println("After: " + afterJSON.toJSON());

        System.out.println(before.equals(afterJSON));
    }
}
