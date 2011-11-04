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
package com.netscape.certsrv.ca;


import netscape.security.x509.Extension;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;


/**
 * An interface representing a CRL extension plugin.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public interface ICMSCRLExtension {

    /**
     * Returns CRL extension OID string.
     *
     * @return OID of CRL extension
     */
    public String getCRLExtOID();

    /**
     * Sets extension criticality and returns extension
     * with new criticality.
     *
     * @param ext CRL extension that will change criticality
     * @param critical new criticality to be assigned to CRL extension
     * @return extension with new criticality
     */
    Extension setCRLExtensionCriticality(Extension ext,
        boolean critical);

    /**
     * Builds new CRL extension based on configuration data,
     * issuing point information, and criticality.
     *
     * @param config configuration store
     * @param crlIssuingPoint CRL issuing point
     * @param critical criticality to be assigned to CRL extension
     * @return extension new CRL extension
     */
    Extension getCRLExtension(IConfigStore config,
        Object crlIssuingPoint,
        boolean critical);

    /**
     * Reads configuration data and converts them to name value pairs.
     *
     * @param config configuration store
     * @param nvp name value pairs obtained from configuration data 
     */
    public void getConfigParams(IConfigStore config,
        NameValuePairs nvp);
} 
