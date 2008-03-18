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

import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * CA Certificate Setting
 *
 * @author Christine Ho
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSCACertSettingPanel extends CMSCertSettingPanel {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "CACERTSETTING";
    private PanelMapperConfigDialog mDialog = null;
    private CMSTabPanel mParent;
    private static final String HELPINDEX = 
      "configuration-ca-ldappublish-cacert-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSCACertSettingPanel(CMSTabPanel parent) {
        super(PANEL_NAME, parent);
        mParent = parent;
        mHelpToken = HELPINDEX;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
     
    /**
     * Actual UI construction
     */
    public void init() {
        super.init();
        
        //XXX B1 - disable the publisher configuration
        mPublisher.setEnabled(false);
        //XXX B1 - disable the publisher configuration
        
        refresh();
    }

    public void refresh() {
        _model.progressStart();
        NameValuePairs nvp = new NameValuePairs();
        nvp.add(Constants.PR_MAPPER, "");
        nvp.add(Constants.PR_PUBLISHER, "");

        try {
            NameValuePairs val = _admin.read(DestDef.DEST_CA_ADMIN,
              ScopeDef.SC_CACERT, Constants.RS_ID_CONFIG, nvp);

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
    public boolean applyCallback() {
        clearDirtyFlag();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback() {
        refresh();
        return true;
    }
    
    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/ 
     
    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mMapper)) {
            Debug.println("Edit Mapper Config");
            mDialog = new PanelMapperConfigDialog(_model.getFrame(), _admin);
            mDialog.showDialog(_mapper.getText(), 
                    DestDef.DEST_CA_ADMIN, ScopeDef.SC_CACERT);
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
    
    /* get config parameters associated with each mapper
    private NameValueParis getConfig() throws EAdminException {
        
        NameValuePairs response = _admin.read(DestDef.DEST_CA_ADMIN,
              ScopeDef.SC_CAMAPPER, _mapper.getText()], 
              new NameValuePairs());
        return response;
    }
    */
    
    /*send configuration to server 
    private void sendConfig(NameValuePairs response) {
        
        response.add(Constants.PR_MAPPER, MAPPER[_mapper.getSelectedIndex()]);
        _model.progressStart();
        try {
            _admin.modify(DestDef.DEST_CA_ADMIN,
              ScopeDef.SC_CACERT, Constants.RS_ID_CONFIG, response);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            _model.progressStop();
            return false;
        }
        _model.progressStop();
       
    }
    */
    
    private void populate(NameValuePairs nvps) {
        for (int i=0; i<nvps.size(); i++) {
            NameValuePair nvp = nvps.elementAt(i);
            String name = nvp.getName();
            if (name.equals(Constants.PR_MAPPER)) {
                _mapper.setText(nvp.getValue());
            } else if (name.equals(Constants.PR_PUBLISHER)) {
                _publisher.setText(nvp.getValue());
            }
        }
    }     
}

