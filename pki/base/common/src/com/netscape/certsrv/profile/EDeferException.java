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
package com.netscape.certsrv.profile;

import com.netscape.certsrv.base.*;

/**
 * This represents a profile specific exception. The 
 * framework raises this exception when a request is 
 * deferred. 
 * <p>
 * A deferred request will not be processed
 * immediately. Manual approval is required for
 * processing the request again.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class EDeferException extends EProfileException {

    /**
     * Creates a defer exception.
     *
     * @param msg localized message that will be 
     *            displayed to end user. This message 
     *            should indicate the reason why a request 
     *            is deferred.
     */
    public EDeferException(String msg) {
        super(msg);
    }
}
