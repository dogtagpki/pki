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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminUtil;

/**
 * Self Tests Implementation Information viewer
 *
 * @author Matthew Harmsen
 * @author Thomas Kwan
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ViewSelfTestsDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private JTextArea mTextArea;
    private JButton mOK;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ViewSelfTestsDialog( JFrame parent, String title )
    {
        super( parent, true );
        setSize( 550, 150 );
        setTitle( title );
        setLocationRelativeTo( parent );
        getRootPane().setDoubleBuffered( true );
        setDisplay();
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * show the description
     */
    public void showDialog( String desc )
    {
        //initialize and setup
        mTextArea.setText( CMSAdminUtil.wrapText( desc, 80 ) );
        mTextArea.setCaretPosition( 0 );
        this.setVisible(true);
    }

    /*==========================================================
     * EVENT HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed( ActionEvent evt )
    {
        if( evt.getSource().equals( mOK ) ) {
            this.setVisible(false);
        }
    }

    /*==========================================================
     * private methods
     *==========================================================*/
    private void setDisplay()
    {
        getContentPane().setLayout( new BorderLayout() );
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout( gb );

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC( gbc );
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints( content, gbc );
        center.add( content );

        //action panel
        JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC( gbc );
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints( action, gbc );
        center.add( action );

        getContentPane().add( "Center", center );
    }

    private JPanel makeActionPane()
    {
        // add OK button
        mOK = new JButton();
        mOK.setText( "OK" );
        mOK.addActionListener( this );
        Dimension d = mOK.getMinimumSize();
        if( d.width < CMSAdminUtil.DEFAULT_BUTTON_SIZE ) {
            d.width = CMSAdminUtil.DEFAULT_BUTTON_SIZE;
            mOK.setMinimumSize( d );
        }
        JButton[] buttons = { mOK };
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane()
    {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout( gb3 );

        CMSAdminUtil.resetGBC( gbc );
        mTextArea = new JTextArea( "" );
        mTextArea.setEditable( false );
        mTextArea.setBackground( getBackground() );

        JScrollPane
        scrollPanel = new JScrollPane( mTextArea,
                                       JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                       JScrollPane.HORIZONTAL_SCROLLBAR_NEVER );
        scrollPanel.setAlignmentX( LEFT_ALIGNMENT );
        scrollPanel.setAlignmentY( TOP_ALIGNMENT );
        scrollPanel.setBackground( getBackground() );
        scrollPanel.setBorder( BorderFactory.createLoweredBevelBorder() );
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb3.setConstraints( scrollPanel, gbc );
        content.add( scrollPanel );

        return content;
    }
}
