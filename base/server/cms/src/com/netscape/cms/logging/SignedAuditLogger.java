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
package com.netscape.cms.logging;

import com.netscape.certsrv.logging.ILogger;

/**
 * A class represents certificate server logger
 * implementation.
 * <P>
 *
 * @author thomask
 * @author mzhao
 * @version $Revision$, $Date$
 */
public class SignedAuditLogger extends Logger {

    private final static SignedAuditLogger logger =
            new SignedAuditLogger();

    public SignedAuditLogger() {
        super(new SignedAuditEventFactory(),
                ILogger.EV_SIGNED_AUDIT,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY);
    }

    public static SignedAuditLogger getLogger() {
        return logger;
    }
}
