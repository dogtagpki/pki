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
package com.netscape.cmscore.cert;


import java.io.*;
import java.util.*;
import java.text.*;
import java.security.PublicKey;
import java.security.cert.*;
import netscape.security.util.*;
import netscape.security.x509.*;
import com.netscape.cmscore.util.*;
import com.netscape.certsrv.base.*;


/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class CertPrettyPrint extends netscape.security.util.CertPrettyPrint implements ICertPrettyPrint {

    public CertPrettyPrint(Certificate cert) {
        super(cert);
    }
}
