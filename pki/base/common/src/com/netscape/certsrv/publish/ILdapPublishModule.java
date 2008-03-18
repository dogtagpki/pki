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
package com.netscape.certsrv.publish;


import com.netscape.certsrv.base.*;
import com.netscape.certsrv.request.*;
import java.security.cert.*;
import com.netscape.certsrv.ldap.*;


/**  
 * Handles requests to  perform Ldap publishing.
 *
 * @version $Revision: 14561 $ $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface ILdapPublishModule extends IRequestListener {

    /**
     * initialize ldap publishing module with config store
     */
    //	public void init(ICertAuthority owner, IConfigStore config) 
    //		throws EBaseException, ELdapException;

    /**
     * Accepts completed requests from an authority and 
     * performs ldap publishing.
     * @param request The publishing request. 
     */
    public void accept(IRequest request);
}

