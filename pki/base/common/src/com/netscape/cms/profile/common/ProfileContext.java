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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.common;


import java.util.*;

import com.netscape.certsrv.profile.*;


/**
 * This class implements the profile context.
 *
 * @version $Revision$, $Date$
 */
public class ProfileContext implements IProfileContext {
    private Hashtable m_Attrs = new Hashtable();

    public void set(String name, String value) {
        m_Attrs.put(name, value);
    }

    public String get(String name) {
        return (String) m_Attrs.get(name);
    }
}
