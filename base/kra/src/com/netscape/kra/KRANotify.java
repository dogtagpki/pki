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
package com.netscape.kra;

import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.request.ARequestNotifier;

/**
 * A class represents a KRA request queue notify. This
 * object will be invoked by the request subsystem
 * when a request is requested for processing.
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KRANotify extends ARequestNotifier {
    @SuppressWarnings("unused")
    private IKeyRecoveryAuthority mKRA;

    /**
     * default constructor
     */
    public KRANotify() {
        super();
    }

    /**
     * Creates KRA notify.
     */
    public KRANotify(IKeyRecoveryAuthority kra) {
        super();
        mKRA = kra;
    }

    // XXX may want to do something else with mKRA ?
}
