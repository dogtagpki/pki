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
package com.netscape.certsrv.password;


/**
 * Configuration Wizard Password quality checker interface.
 * <P>
 * 
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IConfigPasswordCheck {

    /**
     * Check if the password meets the quality requirement
     * @param pwd the given password
     * @return true if the password meets the quality requirement; otherwise false
     */
    public boolean isGoodConfigPassword(String pwd);

    /**
     * Returns a reason if the password doesnt meet the quality requirement.
     * @param pwd the given password
     * @return a reason if the password quality requirement is not met.
     */
    public String getConfigReason(String pwd);
}

