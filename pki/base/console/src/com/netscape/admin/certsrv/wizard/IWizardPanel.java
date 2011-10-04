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
package com.netscape.admin.certsrv.wizard;

import javax.swing.*;

/**
 * Interface for WizardWidget delegation.<p>
 * The methods will be call in the following order: <br>
 * <pre>
 *      initialize(WizardInfo);
 *      validate();
 *      conclude(WizardInfo);
 *      getUpdateInfo(WizardInfo);
 * </pre>
 * For example, you can assume the WizardPanel is validated already
 * when getUpdateInfo() is called.<p>
 * REMEMBER TO SET THE ERROR WHEN ERROR OCCURRED!<p>
 *
 * @author  jpanchen
 * @version %I%, %G%
 * @date	 	12/02/97
 * @see     com.netscape.admin.certsrv.wizard
 */
public interface IWizardPanel {

    /**
     * Initialize the panel. Data are passed in
     * as WinzardInfo. Class implements this interface is responsible
     * for maintaining the state information. Usually, you just
     * need to have a dummy function if you are not using
     * information provided by the previous screen to config/generate
     * this screen. If error occurred, return false and set error
     * message to be retrieved by getErrorMessage().
     * @return true if ok; otherwise, false.
     */
    public abstract boolean initializePanel(WizardInfo info);

    /**
     * Verify the panel. The implementation should check for
     * errors at this time. If error found, return false, and
     * set error message to be retrieved by getErrorMessage().
     * @return true if ok; otherwise, false.
     */
    public abstract boolean validatePanel();

    /**
     * Performs post processing. This function is call after
     * the panel is verified.
     * Ususally the LAST IWizardPanel use this method to perform
     * save/update operation on the server via cgi/rmi/ldap.
     * Similar to validate(), if error found, return false and
     * set error message to be retrieved by getErrorMessage().
     * @return true if ok; otherwise, false.
     */
    public abstract boolean concludePanel(WizardInfo info);

    /**
     * Save panel information into the WizardInfo to be passed
     * on to the next screen.
     */
    public abstract void getUpdateInfo(WizardInfo info);

    /**
     * Error Message delegation. This method should return
     * an I18N supported string detailing the error.
     * @return string represenation of error
     */
    public abstract String getErrorMessage();

	/**
	 * Display Help for this page
	 */
    public abstract void callHelp();

	/**
	 * Get title for this page
	 */
    public abstract String getTitle();

    public boolean isLastPage();

}
