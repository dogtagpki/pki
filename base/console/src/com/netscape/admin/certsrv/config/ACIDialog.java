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
import java.awt.Color;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.JButtonFactory;

/**
 * ACL Editor
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ACIDialog extends JDialog
    implements ActionListener, MouseListener
{

    private static final long serialVersionUID = 1L;

    private final static String PREFIX = "ACIDIALOG";
    private static final String HELPINDEX =
      "configuration-authorization";
    private JFrame mParentFrame;
    private JButton mOK, mCancel, mHelp;
    private ResourceBundle mResource;
    private boolean mDone = false;
    private JTextArea mACIText, mHelpArea;
    private String mOperations;
    private JList<String> mList;
    private JScrollPane mScrollPane;
    private DefaultListModel<String> mDataModel;
    private JRadioButton mAllowBtn, mDenyBtn;
    private String mHelpToken;
    private AdminConnection mConnection;

    public ACIDialog(JFrame parent, String ops, AdminConnection adminConn) {
        super(parent,true);
        mParentFrame = parent;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new DefaultListModel<>();
        mConnection = adminConn;
        mOperations = ops;
        mHelpToken = HELPINDEX;
        setSize(360, 350);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mCancel)) {
            mDone = false;
            this.hide();
        } else if (evt.getSource().equals(mOK)) {
            String acl = mACIText.getText().trim();
            Vector<String> v = parseExpressions(acl);

            NameValuePairs response;
            try {
                response = mConnection.search(DestDef.DEST_ACL_ADMIN,
                               ScopeDef.SC_EVALUATOR_TYPES,
                               new NameValuePairs());
            } catch (EAdminException e) {
                //display error dialog
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }

            boolean allCorrect = true;
            for (String element : v) {
                if (!validateSyntax(element, response)) {
                    allCorrect = false;
                    break;
                }
            }

            if (v.size() > 0 && allCorrect) {
                mDone = true;
                this.hide();
            } else {
                String msg = mResource.getString(
                  PREFIX+"_DIALOG_INCORRECTSYNTAX_MESSAGE");
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  msg ,CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
        } else if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    private Vector<String> parseExpressions(String s) {
        String str = s;
        Vector<String> v = new Vector<String>();

        while (str.length() > 0) {
            int orIndex = str.indexOf("||");
            int andIndex = str.indexOf("&&");

            if (orIndex == -1 && andIndex == -1) {
                if (str.length() > 0)
                    v.addElement(str.trim());
                return v;

            // || first
            } else if (andIndex == -1 || (orIndex != -1 && orIndex < andIndex)) {
                v.addElement(str.substring(0, orIndex).trim());

                str = str.substring(orIndex+2);
            // && first
            } else {
                v.addElement(str.substring(0, andIndex).trim());
                str = str.substring(andIndex+2);
            }
        }

        return v;
    }

    public void showDialog(String aci, boolean newACI) {
        if (newACI) {
            mList.clearSelection();
            mList.invalidate();
            mList.validate();
            mList.repaint(1);
            mAllowBtn.setSelected(true);
            mAllowBtn.invalidate();
            mAllowBtn.validate();
            mAllowBtn.repaint(1);
            mDenyBtn.setSelected(false);
            mDenyBtn.invalidate();
            mDenyBtn.validate();
            mDenyBtn.repaint(1);
            mACIText.setText("");
            if (mList.getSelectedIndex() < 0)
                mOK.setEnabled(false);
            else
                mOK.setEnabled(true);
        } else {
            if (aci.startsWith("allow")) {
                mAllowBtn.setSelected(true);
            } else if (aci.startsWith("deny")) {
                mDenyBtn.setSelected(true);
            }
            int startIndex = aci.indexOf("(");
            int endIndex = aci.indexOf(")");
            if ((startIndex > 0) && (endIndex > 0)) {
                String str = aci.substring(startIndex+1, endIndex);
                StringTokenizer tokenizer = new StringTokenizer(str,",");
                int[] indices = new int[tokenizer.countTokens()];
                int i = 0;
                while (tokenizer.hasMoreElements()) {
                    indices[i++] = mDataModel.indexOf(tokenizer.nextElement());
                }
                mList.setSelectedIndices(indices);
            }
            String text = aci.substring(endIndex+1).trim();
            mACIText.setText(text);
        }

        this.show();
    }

    public boolean getOK() {
        return mDone;
    }

    public String getValue() {
        Object[] values = mList.getSelectedValues();
        String result = "";
        if (!mAllowBtn.isSelected() && !mDenyBtn.isSelected())
            return "";
        if (mAllowBtn.isSelected())
            result = result+"allow"+" (";
        else if (mDenyBtn.isSelected())
            result = result+"deny"+" (";
        if ((values == null) || (values.length == 0))
            return "";

        for (int i=0; i<values.length; i++) {
            if (i > 0)
                result = result+","+(String)values[i];
            else if (i == 0)
                result = result+(String)values[i];
            if (i == values.length-1)
                result = result+") ";
        }
        result = result+mACIText.getText();
        return result;
    }

    public void mouseClicked(MouseEvent e) {
        if (e.getSource() == mList) {
            if (mList.getSelectedIndex() < 0)
                mOK.setEnabled(false);
            else
                mOK.setEnabled(true);
            return;
        }

        Component comp = (Component)e.getSource();
        String str = comp.getName();
        String text = "";
        if (str.equals("access")) {
            text = mResource.getString(PREFIX+"_ACCESS_HELP");
        } else if (str.equals("rights")) {
            text = mResource.getString(PREFIX+"_RIGHTS_HELP");
        } else if (str.equals("syntax")) {
            text = mResource.getString(PREFIX+"_SYNTAX_HELP");
        }
        mHelpArea.setText(text);
    }

    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {
    }
    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {
    }

    private boolean validateSyntax(String str, NameValuePairs nvps) {
        for (String name : nvps.keySet()) {
            if (str.startsWith(name)) {
                int len = name.length();
                String leftover = str.substring(len).trim();
                String operators = nvps.get(name);
                StringTokenizer st = new StringTokenizer(operators, ",");
                while (st.hasMoreTokens()) {
                    String token = st.nextToken();
                    if (leftover.startsWith(token))
                        return true;
                }
            }
        }

        return false;
    }

    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gb.setConstraints(content, gbc);
        center.add(content);

        // Help Panel
        JPanel helpPanel = makeHelpPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb.setConstraints(helpPanel, gbc);
        center.add(helpPanel);

        //action panel
        JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
        center.add(action);

        getContentPane().add("Center",center);
    }

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeHelpPanel() {
        JPanel helpPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        helpPanel.setBorder(CMSAdminUtil.makeEtchedBorder());
        helpPanel.setLayout(gb);

        mHelpArea = new JTextArea();
        mHelpArea.setRows(20);
        mHelpArea.setLineWrap(true);
        mHelpArea.setWrapStyleWord(true);
        mHelpArea.setBackground(helpPanel.getBackground());
        mHelpArea.setEditable(false);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
/*
        gbc.insets = new Insets(0,
                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
*/
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
    //    gbc.gridx = 1;
    //    gbc.gridy = 1;
        gb.setConstraints(mHelpArea, gbc);
        helpPanel.add(mHelpArea);
        mHelpArea.setText(mResource.getString(PREFIX+"_INTRO_HELP"));
        return helpPanel;
    }

    private JPanel makeContentPanel() {
        JPanel mainPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mainPanel.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel accessLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "ACCESS", null);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gb.setConstraints(accessLbl, gbc);
        mainPanel.add(accessLbl);
        accessLbl.addMouseListener(this);
        accessLbl.setName("access");
        ButtonGroup group = new ButtonGroup();

        CMSAdminUtil.resetGBC(gbc);
        //mAllowBtn = new JRadioButton("allow");
        mAllowBtn = CMSAdminUtil.makeJRadioButton(mResource, PREFIX,
          "ALLOW", null, true, this);
        group.add(mAllowBtn);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gb.setConstraints(mAllowBtn, gbc);
        mainPanel.add(mAllowBtn);

        CMSAdminUtil.resetGBC(gbc);
        //mDenyBtn = new JRadioButton("deny");
        mDenyBtn = CMSAdminUtil.makeJRadioButton(mResource, PREFIX,
          "DENY", null, false, this);
        group.add(mDenyBtn);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gb.setConstraints(mDenyBtn, gbc);
        mainPanel.add(mDenyBtn);

        CMSAdminUtil.resetGBC(gbc);
        JLabel opsLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "RIGHTS", null);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        //gbc.gridwidth = gbc.REMAINDER;
        gb.setConstraints(opsLabel, gbc);
        mainPanel.add(opsLabel);
        opsLabel.addMouseListener(this);
        opsLabel.setName("rights");

        mList = CMSAdminUtil.makeJList(mDataModel, 3);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

        if (!mOperations.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(mOperations, ",");
            while (tokenizer.hasMoreTokens()) {
                mDataModel.addElement(tokenizer.nextToken());
            }
        }

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gb.setConstraints(mScrollPane, gbc);
        mainPanel.add(mScrollPane);
/*
        JPanel listPane = makeListPane();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gb.setConstraints(listPane, gbc);
        mainPanel.add(listPane);
*/

        CMSAdminUtil.resetGBC(gbc);
        JLabel attrLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
          "SYNTAX", null);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gb.setConstraints(attrLabel, gbc);
        mainPanel.add(attrLabel);
        attrLabel.addMouseListener(this);
        attrLabel.setName("syntax");

        CMSAdminUtil.resetGBC(gbc);
        mACIText = new JTextArea();
        mACIText.setRows(20);
        mACIText.setLineWrap(true);
        mACIText.setWrapStyleWord(true);
        JScrollPane scrollPane = createScrollPane(mACIText);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
    //    gbc.gridx = 1;
    //    gbc.gridy = 1;
        gb.setConstraints(scrollPane, gbc);
        mainPanel.add(scrollPane);

        return mainPanel;
    }

    private JScrollPane createScrollPane(JComponent component) {

        JScrollPane scrollPane = new JScrollPane(component,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setBackground(getBackground());
        scrollPane.setAlignmentX(LEFT_ALIGNMENT);
        scrollPane.setAlignmentY(TOP_ALIGNMENT);
        scrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        return scrollPane;
    }
}
