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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.password.EPasswordCheckException;
import com.netscape.certsrv.password.IConfigPasswordCheck;
import com.netscape.certsrv.password.IPasswordCheck;

/**
 * This class checks the given password if it meets the specific requirements.
 * For example, it can also specify the format of the password which has to
 * be 8 characters long and must be in alphanumeric.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class PasswordChecker implements IPasswordCheck, IConfigPasswordCheck {

    public static final int MIN_LEN = 8;

    /**
     * Default constructor.
     */
    public PasswordChecker() {
    }

    public boolean isGoodConfigPassword(String mPassword) {
        if (mPassword == null || mPassword.length() == 0) {
            return false;
        } else if (mPassword.length() < MIN_LEN) {
            return false;
        }
        return true;
    }

    public String getConfigReason(String mPassword) {
        if (mPassword == null || mPassword.length() == 0) {
            EPasswordCheckException e = new EPasswordCheckException(
                    "Empty Password");

            return e.toString();
        } else if (mPassword.length() < MIN_LEN) {
            EPasswordCheckException e = new EPasswordCheckException(
                    "Minimium Length is " + MIN_LEN);

            return e.toString();
        }
        return null;
    }

    /**
     * Returns true if the given password meets the quality requirement;
     * otherwise returns false.
     *
     * @param mPassword The given password being checked.
     * @return true if the password meets the quality requirement; otherwise
     *         returns false.
     */
    public boolean isGoodPassword(String mPassword) {
        if (mPassword == null || mPassword.length() == 0) {
            return false;
        } else if (mPassword.length() < MIN_LEN) {
            return false;
        }
        return true;
    }

    /**
     * Returns a reason if the password doesnt meet the quality requirement.
     *
     * @return string as a reason if the password quality requirement is not met.
     */
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
