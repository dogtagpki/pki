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
package com.netscape.certsrv.tks;


import java.io.*;
import java.net.*;
import java.util.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.policy.*;
import com.netscape.certsrv.publish.*;
import com.netscape.certsrv.request.*;


/**
 * An interface represents a Registration Authority that is
 * responsible for certificate enrollment operations.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ITKSAuthority extends ISubsystem {
    public static final String ID = "tks";

    public static final String PROP_POLICY = "Policy";
    public static final String PROP_REGISTRATION = "Registration";
    public static final String PROP_GATEWAY = "gateway";
    public static final String PROP_NICKNAME = "certNickname";
    //public final static String PROP_PUBLISH_SUBSTORE = "publish";
    //public final static String PROP_LDAP_PUBLISH_SUBSTORE = "ldappublish";
    public final static String PROP_CONNECTOR = "connector";
    public final static String PROP_NEW_NICKNAME = "newNickname";



    /**
     * Retrieves the request queue of this registration authority.
     *
     * @return RA's request queue
     */
    public IRequestQueue getRequestQueue();

    /**
     * Returns the nickname of the RA certificate.
     *
     * @return the nickname of the RA certificate
     */
    public String getNickname();

}
