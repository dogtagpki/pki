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
package com.netscape.cms.servlet.admin;


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authentication.*;


/**
 * Authentication Credentials as input to the authMgr
 * <P>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class AuthCredentials implements IAuthCredentials {
    private Hashtable authCreds = null;
    // Inserted by bskim 
    private IArgBlock argblk = null;
    // Insert end
    
    public AuthCredentials() {
        authCreds = new Hashtable();
    }

    /**
     * sets a credential with credential name and the credential
     * @param name credential name
     * @param cred credential
     * @exception com.netscape.certsrv.base.EBaseException NullPointerException
     */
    public void set(String name, Object cred)throws EBaseException {
        if (cred == null) {
            throw new EBaseException("AuthCredentials.set()");
        }

        authCreds.put(name, cred);
    }

    /**
     * returns the credential to which the specified name is mapped in this
     *	 credential set
     * @param name credential name
     * @return the named authentication credential
     */
    public Object get(String name) {
        return ((Object) authCreds.get(name));
    }

    /**
     * removes the name and its corresponding credential from this
     *	 credential set.  This method does nothing if the named
     *	 credential is not in the credential set.
     * @param name credential name
     */
    public void delete(String name) {
        authCreds.remove(name);
    }

    /**
     * returns an enumeration of the credentials in this credential
     *	 set.  Use the Enumeration methods on the returned object to
     *	 fetch the elements sequentially.
     * @return an enumeration of the values in this credential set
     * @see java.util.Enumeration
     */
    public Enumeration getElements() {
        return (authCreds.elements());
    }
    
    // Inserted by bskim
    public void setArgBlock(IArgBlock blk) {
        argblk = blk;
        return;
    }        

    // Insert end
    
    public IArgBlock getArgBlock() {
        return argblk;
    }        
    // Insert end
}

