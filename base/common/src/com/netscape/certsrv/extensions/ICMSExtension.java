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
package com.netscape.certsrv.extensions;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.Extension;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;

/**
 * CMS extension interface, for creating extensions from http input and
 * displaying extensions to html forms.
 *
 * @version $Revision$, $Date$
 */
public interface ICMSExtension {
    public static String EXT_IS_CRITICAL = "isCritical";

    public static String EXT_PREFIX = "ext_";

    /**
     * initialize from configuration file
     */
    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException;

    /**
     * Get name of this extension.
     *
     * @return the name of this CMS extension, for
     */
    public String getName();

    /**
     * Get object identifier associated with this extension.
     */
    public ObjectIdentifier getOID();

    /**
     * Get an instance of the extension given http input.
     *
     * @return an instance of the extension.
     */
    public Extension getExtension(IArgBlock argblock)
            throws EBaseException;

    /**
     * Get Javascript name value pairs to put into the request processing
     * template.
     *
     * @return name value pairs
     */
    public IArgBlock getFormParams(Extension extension)
            throws EBaseException;

}
