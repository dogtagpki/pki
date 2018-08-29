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

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.CMSBaseResourceModel;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Self Tests setting tab
 *
 * @author Matt Harmsen
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSSelfTestsPanel extends CMSBaseTab
{
    private static final String PROP_TITLE = "On-Demand Self Tests Results";
    private static String PANEL_NAME = "SELFTESTS";
    private AdminConnection mAdmin;
    private JButton mOnDemand;
    private CMSBaseResourceModel mModel;
    private static final String HELPINDEX =
        "configuration-overview";
    private ViewSelfTestsDialog mViewer = null;


    public CMSSelfTestsPanel( CMSTabPanel parent )
    {
        super( PANEL_NAME, parent );
        mModel = parent.getResourceModel();
        mHelpToken = HELPINDEX;
    }


    public void init()
    {
        Debug.println( "SelfTestsPanel: init()" );
        mAdmin = mModel.getServerInfo().getAdmin();
        JPanel selftestsInfo = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC( gbc );
        mCenterPanel.setLayout( gb );
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints( selftestsInfo, gbc );
        mCenterPanel.add( selftestsInfo );

        GridBagLayout gb1 = new GridBagLayout();
        selftestsInfo.setLayout( gb1 );

        // self tests border
        selftestsInfo.setBorder( new CompoundBorder(
                                 BorderFactory.createTitledBorder(
                                 mResource.getString(
                                 "SELFTESTS_BORDER_LABEL" ) ),
                                 new EmptyBorder( -3,
                                                   0,
                                                  DIFFERENT_COMPONENT_SPACE - 3,
                                                  0 ) ) );

        // add on-demand self tests label
        CMSAdminUtil.resetGBC( gbc );
        JLabel onDemandLabel = makeJLabel( "ONDEMAND" );
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets( COMPONENT_SPACE,
                                 DIFFERENT_COMPONENT_SPACE,
                                 0,
                                 0 );
        selftestsInfo.add( onDemandLabel, gbc );


        // add run button for on-demand self tests
        mOnDemand = makeJButton( "RUN" );
        JButton[] buttons = { mOnDemand };
        JButtonFactory.resize( buttons );
        CMSAdminUtil.makeJButtonVPanel( buttons );
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;
        gbc.gridwidth = GridBagConstraints.RELATIVE;
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets( COMPONENT_SPACE,
                                 DIFFERENT_COMPONENT_SPACE,
                                 0,
                                 DIFFERENT_COMPONENT_SPACE );
        selftestsInfo.add( mOnDemand, gbc );

        // add space after the run button
        JLabel dummy = new JLabel(" ");
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridx = GridBagConstraints.RELATIVE;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets( COMPONENT_SPACE,
                                 0,
                                 COMPONENT_SPACE,
                                 0 );
        selftestsInfo.add( dummy, gbc );

        refresh();
    }


    public void refresh()
    {
        clearDirtyFlag();
    }


    public void actionPerformed( ActionEvent evt )
    {
        super.actionPerformed( evt );

        NameValuePairs nvps = new NameValuePairs();
        NameValuePairs nvps1;

        nvps.put(Constants.PR_RUN_SELFTESTS_ON_DEMAND, Constants.TRUE);

        if( evt.getSource().equals( mOnDemand ) ) {
            Debug.println( "Run self tests on-demand . . ." );

            mModel.progressStart();
            try {
                nvps1 = mAdmin.process( DestDef.DEST_SERVER_ADMIN,
                                        ScopeDef.SC_SELFTESTS,
                                        Constants.RS_ID_CONFIG,
                                        nvps );
                // show server response
                String responseClass = "";
                String response = "";
                boolean first = true;
                for (String name : nvps1.keySet()) {
                    String value = nvps1.get(name);
                    if (first) {
                        first = false;
                        responseClass = value;
                    } else {
                        response = response + value + "\n";
                    }
                }

                Debug.println( ". . . class \""
                             + responseClass
                             + "\" responded with "
                             + "on-demand self tests results." );

                if( mViewer == null ) {
                    mViewer = new ViewSelfTestsDialog( mModel.getFrame(),
                                                       PROP_TITLE );
                }

                mViewer.showDialog( response );
            } catch( EAdminException e ) {
                showErrorDialog( e.toString() );
                mModel.progressStop();
                return;
            }
            mModel.progressStop();
        }

        clearDirtyFlag();
        return;
    }


    /**
     * Implementation for saving panel information
     * @return true if save successful; otherwise, false.
     */
    public boolean applyCallback()
    {
        clearDirtyFlag();
        return true;
    }


    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    public boolean resetCallback()
    {
        refresh();
        return true;
    }
}

