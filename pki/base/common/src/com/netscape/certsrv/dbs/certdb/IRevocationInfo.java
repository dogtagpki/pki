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
package com.netscape.certsrv.dbs.certdb;


import java.util.*;
import java.io.*;
import java.math.*;
import java.security.cert.*;
import netscape.security.x509.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import com.netscape.certsrv.base.*;


/**
 * A class represents a certificate revocation info. This
 * object is written as an attribute of certificate record 
 * which essentially signifies a revocation act.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface IRevocationInfo {

    /**
     * Retrieves revocation date.
     *
     * @return revocation date
     */
    public Date getRevocationDate();

    /**
     * Retrieves CRL entry extensions.
     *
     * @return CRL entry extensions
     */
    public CRLExtensions getCRLEntryExtensions();
}
