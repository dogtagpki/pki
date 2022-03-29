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
package com.netscape.admin.certsrv.config;

import java.awt.event.ActionEvent;

import com.netscape.admin.certsrv.EAdminException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

/**
 * User Certificate Setting
 *
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class CMSUserCertSettingPanel extends CMSCertSettingPanel {

    /*==========================================================
     * variables
     *==========================================================*/
    private String _servletName;    //destination name
    private CMSTabPanel mParent;
    private PanelMapperConfigDialog mDialog = null;
    private static final String RAHELPINDEX =
     "configuration-ra-ldappublish-usercert-help";
    private static final String CAHELPINDEX =
     "configuration-ca-ldappublish-usercert-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSUserCertSettingPanel(String panelName, CMSTabPanel parent) {
        super(panelName, parent);
        _servletName = getServletName(panelName);
        mParent = parent;
        if (panelName.equals("RAUSERCERTSETTING"))
            mHelpToken = RAHELPINDEX;
        else
            mHelpToken = CAHELPINDEX;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual UI construction
     */
    @Override
    public void init() {
        super.init();

        //XXX B1 - disable the publisher configuration
        mPublisher.setEnabled(false);
        //XXX B1 - disable the publisher configuration

        refresh();
    }

    @Override
    public void refresh() {
        _model.progressStart();
        NameValuePairs nvp = new NameValuePairs();
        nvp.put(Constants.PR_MAPPER, "");
        nvp.put(Constants.PR_PUBLISHER, "");

        try {
            NameValuePairs val = _admin.read(_servletName,
              ScopeDef.SC_USERCERT, Constants.RS_ID_CONFIG, nvp);

            populate(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
        }
        _model.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }


    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean applyCallback() {
        clearDirtyFlag();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean resetCallback() {
        refresh();
        return true;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mMapper)) {
            Debug.println("Edit Mapper Config");
            mDialog = new PanelMapperConfigDialog(_model.getFrame(), _admin);
            mDialog.showDialog(_mapper.getText(),
                _servletName, ScopeDef.SC_USERCERT);
            if (!mDialog.isOK())
                return;
            refresh();
        } else if (e.getSource().equals(mPublisher)) {
            //Debug.println("Edit Publisher Config");
        }
    }

    /*==========================================================
	 * private methods
     *==========================================================*/
    private String getServletName(String panelName) {
        if (panelName.equals("CAUSERCERTSETTING"))
            return DestDef.DEST_CA_ADMIN;
        return DestDef.DEST_RA_ADMIN;
    }

    private void populate(NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            String value = nvps.get(name);
            if (name.equals(Constants.PR_MAPPER)) {
                _mapper.setText(value);
            } else if (name.equals(Constants.PR_PUBLISHER)) {
                _publisher.setText(value);
            }
        }
    }

}

