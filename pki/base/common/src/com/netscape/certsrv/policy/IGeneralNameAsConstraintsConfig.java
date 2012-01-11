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
package com.netscape.certsrv.policy;

import java.util.Vector;

import netscape.security.x509.GeneralName;

/**
 * Class that can be used to form general names from configuration file.
 * Used by policies and extension commands.
 * <P>
 * 
 * <PRE>
 * NOTE:  The Policy Framework has been replaced by the Profile Framework.
 * </PRE>
 * <P>
 * 
 * @deprecated
 * @version $Revision$, $Date$
 */
public interface IGeneralNameAsConstraintsConfig {

    /**
     * Retrieves instance parameters.
     * 
     * @param params parameters
     */
    public void getInstanceParams(Vector<String> params);

    /**
     * Retrieves the general name.
     * 
     * @return general name
     */
    public GeneralName getGeneralName();

}
