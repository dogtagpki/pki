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


import java.util.*;


/**
 * This interface represents a CRL pretty print handler.
 * It converts a CRL object into a printable CRL string.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface ICRLPrettyPrint {

    /**
     * Retrieves the printable CRL string.
     *
     * @param clientLocale end user clocale
     * @param crlSize CRL size
     * @param pageStart starting page number
     * @param pageSize page size in rows
     * @return printable CRL string
     */
    public String toString(Locale clientLocale, long crlSize, long pageStart, long pageSize);

    /**
     * Retrieves the printable CRL string.
     *
     * @param clientLocale end user clocale
     * @return printable CRL string
     */
    public String toString(Locale clientLocale);
}
