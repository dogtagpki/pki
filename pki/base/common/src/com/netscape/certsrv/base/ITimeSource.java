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
package com.netscape.certsrv.base;

import java.util.Date;

/**
 * This interface represents a time source where current time can be retrieved.
 * CMS is installed with a default time source that returns current time based
 * on the system time. It is possible to register a time source that returns the
 * current time from a NTP server.
 * 
 * @version $Revision$, $Date$
 */
public interface ITimeSource {

    /**
     * Retrieves current time and date.
     * 
     * @return current time and date
     */
    public Date getCurrentDate();

}
