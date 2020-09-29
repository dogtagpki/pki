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
package org.dogtagpki.legacy.policy;

import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;

import org.mozilla.jss.netscape.security.x509.GeneralName;

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
 * @version $Revision$, $Date$
 */
public interface IGeneralNameConfig {

    /**
     * Forms a general name from string.
     *
     * @param value general name in string
     * @return general name object
     * @exception EBaseException failed to form general name
     */
    public GeneralName formGeneralName(String value)
            throws EBaseException;

    /**
     * Forms general names from the given value.
     *
     * @param value general name in string
     * @return a vector of general names
     * @exception EBaseException failed to form general name
     */
    public Vector<GeneralName> formGeneralNames(Object value)
            throws EBaseException;

    /**
     * Retrieves the instance parameters.
     *
     * @param params parameters
     */
    public void getInstanceParams(Vector<String> params);
}
