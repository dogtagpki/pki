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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

/**
 * This represents a profile specific exception for handling
 * CMC popRequired condition.
 * The framework raises this exception when a request is missing POP
 * (Proof Of Possession)
 * <p>
 * A CMC request with missing POP will not be processed immediately.
 * Round trip is required to return with CMC direct POP (DecryptedPOP)
 * for processing the request again.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class ECMCPopRequiredException extends EProfileException {

    /**
     *
     */
    private static final long serialVersionUID = 8328983412028345364L;

    /**
     * Creates a defer exception.
     *
     * @param msg localized message that will be
     *            displayed to end user. This message
     *            should indicate the reason why a request
     *            is deferred.
     */
    public ECMCPopRequiredException(String msg) {
        super(msg);
    }

    public ECMCPopRequiredException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public ECMCPopRequiredException(Throwable cause) {
        super(cause.getMessage(), cause);
    }
}
