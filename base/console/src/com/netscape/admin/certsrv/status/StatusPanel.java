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
package com.netscape.admin.certsrv.status;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;

import java.awt.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;

/**
 * Status to be placed at the right hand side
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.status
 */
public class StatusPanel extends CMSBasePanel
    implements IResourceSelectionListener, IRefreshTab, IRefreshTabPanel
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "STATUSPANEL";

    protected boolean mInit = false;    // true if this panel is initialized
    protected JPanel mStatPanel, mActionPanel;  //panels
    protected JButton mRefresh, mHelp;  //action buttons
    protected JLabel mServerName, mServerVersion, mInstallDate, mServerStart, mServerTime;

    protected CMSBaseResourceModel mModel;
    private AdminConnection mConnection;
    private static final String HELPINDEX = "status-certsrv-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public StatusPanel(CMSBaseResourceModel model) {
        super(PANEL_NAME);
        model.addIResourceSelectionListener(this);
        mModel = model;
        mConnection = model.getServerInfo().getAdmin();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual Instanciation of the UI components
     */
    public void init() {
        setLayout(new BorderLayout());

        //======== stat panel ========================
		mStatPanel = createStatPanel();
		mStatPanel.setBorder(new EmptyBorder(DIFFERENT_COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE));
		add("Center",mStatPanel);

		//====== action panel ========================
		mActionPanel = createActionPanel();
		add("South",mActionPanel);
		refresh();
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //== IResourceListener ===

    public void select(IResourceObject parent, Object viewInstance) {
        if (!mInit) {
            init();
            mInit = true;
        }

        //refresh the screen
        invalidate();
        validate();
        repaint(1);
    }

    public boolean unselect(IResourceObject parent, Object viewInstance) {
        return true;
    }

    public CMSBasePanel getSelectedTab() {
        return this;
    }

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            Debug.println("StatusPanel: Refresh");
            refresh();
        }
        if (e.getSource().equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
        }
    }


    /*==========================================================
	 * protected methods
     *==========================================================*/

    /**
     * create action button panel
     */
    protected JPanel createActionPanel() {
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
	//JButton[] buttons = { mRefresh,mHelp };
	JButton[] buttons = { mRefresh };
		return makeJButtonPanel(buttons,true,true);
    }

    /**
     * create log listing panel
     */
    protected JPanel createStatPanel() {
        JPanel outPanel = new JPanel();
        GridBagLayout gb2 = new GridBagLayout();
        GridBagConstraints gbc2 = new GridBagConstraints();
        outPanel.setLayout(gb2);

		JPanel panel = new JPanel();
		GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        panel.setLayout(gb);
        panel.setBorder(CMSAdminUtil.makeTitledBorder(mResource, PANEL_NAME, "GENERALINFO"));

        CMSAdminUtil.resetGBC(gbc2);
        gbc2.anchor = gbc2.NORTH;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gbc2.gridwidth = gbc2.REMAINDER;
        gbc2.gridheight = gbc2.REMAINDER;
        outPanel.add(panel, gbc2);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = makeJLabel("SERVERNAME");
        mServerName = new JLabel();
        CMSAdminUtil.addEntryField(panel, label1, mServerName, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label2 = makeJLabel("SERVERVERSION");
        mServerVersion = new JLabel();
        CMSAdminUtil.addEntryField(panel, label2, mServerVersion, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label5 = makeJLabel("INSTALLDATE");
        mInstallDate = new JLabel();
        CMSAdminUtil.addEntryField(panel, label5, mInstallDate, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = makeJLabel("SERVERSTARTUP");
        mServerStart = new JLabel();
        CMSAdminUtil.addEntryField(panel, label3, mServerStart, gbc);

        CMSAdminUtil.resetGBC(gbc);
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        JLabel label4 = makeJLabel("SERVERTIME");
        mServerTime = new JLabel();
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE,0);
        panel.add( label4, gbc );

        gbc.gridx++;
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
      		                            COMPONENT_SPACE,COMPONENT_SPACE);
        panel.add( mServerTime, gbc );

		return outPanel;
    }


    //=============================================
	// SEND REQUESTS TO THE SERVER SIDE
	//=============================================

	//retrieve stat from server
	public void refresh() {

	    NameValuePairs params = new NameValuePairs();
	    params.put(Constants.PR_STAT_STARTUP, "");
	    params.put(Constants.PR_STAT_TIME, "");

        NameValuePairs response;
        mModel.progressStart();
        try {
            response = mConnection.read(DestDef.DEST_SERVER_ADMIN,
                               ScopeDef.SC_STAT,
                               Constants.RS_ID_CONFIG,
                               params);
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource,
                                         e.toString(), ERROR_MESSAGE);
            mModel.progressStop();
            return;
        }

        mModel.progressStop();
        Debug.println("StatusPanel: refresh() "+ response.toString());

        //populate data
        mServerName.setText(response.get(Constants.PR_STAT_INSTANCEID));
        mServerVersion.setText(response.get(Constants.PR_STAT_VERSION));
        mInstallDate.setText(response.get(Constants.PR_STAT_INSTALLDATE));
        mServerStart.setText(response.get(Constants.PR_STAT_STARTUP));
        mServerTime.setText(response.get(Constants.PR_STAT_TIME));
	}

}
