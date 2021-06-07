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
package com.netscape.cms.password;

import com.netscape.certsrv.password.EPasswordCheckException;
import com.netscape.certsrv.password.IPasswordCheck;
import com.netscape.cmscore.apps.CMS;

/**
 * This class checks the given password if it meets the specific requirements.
 * For example, it can also specify the format of the password which has to
 * be 8 characters long and must be in alphanumeric.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class PasswordChecker implements IPasswordCheck {

    public static final int MIN_LEN = 8;

    /**
     * Default constructor.
     */
    public PasswordChecker() {
    }

    /**
     * Returns true if the given password meets the quality requirement;
     * otherwise returns false.
     *
     * @param mPassword The given password being checked.
     * @return true if the password meets the quality requirement; otherwise
     *         returns false.
     */
    @Override
    public boolean isGoodPassword(String mPassword) {
        return mPassword != null && mPassword.length() >= MIN_LEN;
    }

    /**
     * Returns a reason if the password doesn't meet the quality requirement.
     *
     * @return string as a reason if the password quality requirement is not met.
     */
    @Override
    public String getReason(String mPassword) {
        if (mPassword == null || mPassword.length() == 0) {
            EPasswordCheckException e = new EPasswordCheckException(
                    CMS.getUserMessage("CMS_PASSWORD_EMPTY_PASSWORD"));

            return e.toString();
        } else if (mPassword.length() < MIN_LEN) {
            EPasswordCheckException e = new EPasswordCheckException(
                    CMS.getUserMessage("CMS_PASSWORD_INVALID_LEN", "" + MIN_LEN));

            return e.toString();
        }
        return null;
    }
}
