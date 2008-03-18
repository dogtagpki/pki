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


import com.netscape.certsrv.ldap.*;
import com.netscape.certsrv.publish.*;


/**
 *
 * Class representing a proxy for a ILdapPublisher.
 *
 * @version $Revision: 14561 $ $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */


public class PublisherProxy {
    private boolean mEnable;
    private ILdapPublisher mPublisher;

    /**
     *
     * Constructs a PublisherProxy based on a ILdapPublisher object and enabled boolean.
     * @param enable Proxy is enabled or not.
     * @param publisher Corresponding ILdapPublisher object.
     */
    public PublisherProxy(boolean enable, ILdapPublisher publisher) {
        mEnable = enable;
        mPublisher = publisher;
    }

    /**
     * Return if enabled or not.
     * @return true if enabled, otherwise false.
     */
    public boolean isEnable() {
        return mEnable;
    }

    /**
     * Return ILdapPublisher object.
     * @return Instance of ILdapPublisher.
     */
    public ILdapPublisher getPublisher() {
        return mPublisher;
    }
}
