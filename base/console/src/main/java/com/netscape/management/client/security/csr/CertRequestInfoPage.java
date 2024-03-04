/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security.csr;
//package com.netscape.management.client.keycert;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


public class CertRequestInfoPage extends JPanel implements SuiConstants, IUIPage, ActionListener, KeyListener {


    JTextField name = new JTextField();
    JTextField phone = new JTextField();
    SingleByteTextField cn = new SingleByteTextField();
    SingleByteTextField email = new SingleByteTextField();
    JTextField o = new JTextField();
    JTextField ou = new JTextField();
    JTextField l = new JTextField();
    JComboBox st;
    JComboBox c;

    JPanel statePanel = new JPanel();

    MultilineLabel dnWarning;
    JTextArea dn = new JTextArea();
    JScrollPane dnScrollPane;
    boolean dnModified = false;

    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.KeyCertWizardResource");

    JButton m_showDNButton;

    JLabel _nameLabel, _phoneLabel, _cnLabel, _emailLabel, _oLabel, _ouLabel, _lLabel, _stLabel, _cLabel;

    Hashtable _sessionData;
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == c) {
            setupState(c.getSelectedItem().toString());
        } else if (e.getSource() == m_showDNButton) {
            advancedInvoked();
        }
    }

    public void keyTyped(KeyEvent e) {}
    public void keyPressed(KeyEvent e) {}
    public void keyReleased(KeyEvent e) {
        if (e.getSource() == c) {
            setupState(c.getSelectedItem().toString());
        } else if (e.getSource() == dn) {
           dnModified = true;
        }
    }

    public Component getComponent() {
	return this;
    }

    public String getPageName() {
	return resource.getString("CertRequestInfoPage", "pageTitle");
    }
    public int getRemainingPageCount() {
	return 2;
    }



    public IUIPage getNextPage() {
        IUIPage contentPage = null;

        if (validated()) {
            contentPage = new CertRequestKeyPage(_sessionData);
        }

	return contentPage;
    }
    public IUIPage getPreviousPage() {
	return null;
    }

    public void addChangeListener(ChangeListener l) {
    }
    public void removeChangeListener(ChangeListener l) {
    }

    public String getHelpURL() {
	return "CertRequestInfoPage";
    }


    private JLabel rightAlignLabel(String label) {
        return new JLabel(label, JLabel.RIGHT);
    }

    private void setupState(String country) {
        String stList;
        statePanel.remove(st);
        try {
            stList = resource.getString("CertRequestInfoPage",
                    "state-"+country.substring(0, 2).toUpperCase());
            if (stList != null && !(stList.equals(""))) {

                StringTokenizer stateTokens =
                        new StringTokenizer(stList, ",", false);
                Vector states = new Vector();
                while (stateTokens.hasMoreTokens()) {
                    states.addElement(stateTokens.nextToken());
                }
                //this will make it load faster.
                //It will do some extra work if we call addItem() one at a time

                st = new JComboBox(states);
                st.setEditable(true);
            }
            else {
                st.removeAllItems();
            }
        }
        catch (Exception e) {
            st.removeAllItems();
        }

        GridBagUtil.constrain(statePanel, st, 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        statePanel.validate();
        statePanel.repaint();

        try {
            st.setSelectedItem( resource.getString("CertRequestInfoPage",
                                                   "defaultState-"+
                                                   country.substring(0, 2).toUpperCase()));

            if (st.getSelectedIndex() == -1) {
                st.setSelectedIndex(0);
            }
        } catch (Exception e2) {
        }

    }

    boolean m_advanceToggleState = true;
    public void advancedInvoked() {
        if (m_advanceToggleState) {
            m_showDNButton.setText(resource.getString("CertRequestInfoPage", "showFields"));
	    m_showDNButton.setToolTipText(resource.getString("CertRequestInfoPage", "showFields_tt"));
            setupAdvancedPanel();
        } else {
            m_showDNButton.setText(resource.getString("CertRequestInfoPage", "showDN"));
	    m_showDNButton.setToolTipText(resource.getString("CertRequestInfoPage", "showDN_tt"));
            setupBasicPanel();
        }
        m_advanceToggleState = !m_advanceToggleState;

        JButtonFactory.resize(m_showDNButton);
        paintAll(getGraphics());
    }
    
    public boolean isPageValidated() {
	return true;
    }

    public boolean validated() {
	_sessionData.put("common_name", cn.getText());
	_sessionData.put("organization", o.getText());
	_sessionData.put("org_unit", ou.getText());
	_sessionData.put("locality", l.getText());
	String c_str = (String)c.getSelectedItem();
	if ((c_str != null) && (c_str.length() >= 2)) {
	    c_str = c_str.substring(0, 2);
	} else {
	    c_str = "";
	}
	_sessionData.put("country" , c_str);
	String st_str = (String)st.getSelectedItem();
	if ((st_str != null) && (st_str.length() >= 2)) {
	    st_str = st_str.substring(0, 2);
	} else {
	    st_str = "";
	}
	_sessionData.put("state" , st_str);
	
        
	setDN();
	_sessionData.put("dn", dn.getText());

        boolean _val = true;

        if ((cn.getText().length() == 0) ||
            (o.getText().length() == 0) ||
            (ou.getText().length() == 0) ||
            (l.getText().length() == 0) ||
	    ((c.getSelectedItem() != null) &&
            (((String)(c.getSelectedItem())).length() < 2)) ||
            ((st.getSelectedItem()!=null) &&
             (((String)(st.getSelectedItem())).length() ==0))) {
            _val = (JOptionPane.showConfirmDialog(this,
                                                 resource.getString("CertRequestInfoPage", "missingField"),
                                                 resource.getString("CertRequestInfoPage", "missingFieldTitle"),
                                                 JOptionPane.YES_NO_OPTION)==JOptionPane.YES_OPTION);
        }

        return _val;
    }

    public CertRequestInfoPage(Hashtable sessionData) {
	super();
        //super(KeyCertUtility.getResourceSet().getString("CertRequestInfoPage", "pageTitle"));

	_sessionData = sessionData;

        setLayout(new GridBagLayout());
        statePanel.setLayout(new GridBagLayout());

        m_showDNButton = JButtonFactory.create(resource.getString("CertRequestInfoPage", "showDN"), this, "ADVANCED");
        JButtonFactory.resize(m_showDNButton);

        String cList = resource.getString("CertRequestInfoPage", "country");

        StringTokenizer countryTokens =
	    new StringTokenizer(cList, ",", false);
        Vector countries = new Vector();
        while (countryTokens.hasMoreTokens()) {
            countries.addElement(countryTokens.nextToken());
        }
	
        st = new JComboBox();
        c = new JComboBox(countries);
	
        _cnLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "cnLabel"));
	_cnLabel.setLabelFor(cn);

        _oLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "oLabel"));
	_oLabel.setLabelFor(o);

        _ouLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "ouLabel"));
	_ouLabel.setLabelFor(ou);

        _lLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "lLabel"));
	_lLabel.setLabelFor(l);

        _stLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "stLabel"));
	_stLabel.setLabelFor(statePanel);

        _cLabel = rightAlignLabel(resource.getString("CertRequestInfoPage", "cLabel"));
	_cLabel.setLabelFor(c);

        try {
            c.setSelectedItem(resource.getString("CertRequestInfoPage", "defaultCountry"));
        } catch (Exception e) {
            Debug.println(e.toString());
        }

        setupState(c.getSelectedItem().toString());

        dnWarning = new MultilineLabel(resource.getString("CertRequestInfoPage", "dnWarning"));
        dn.addKeyListener(this);
        dnScrollPane = new JScrollPane(dn,
                                       JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                       JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        dnScrollPane.setBorder(UIManager.getBorder("TextField"));

        c.addActionListener(this);

        c.addKeyListener(this);

        //cn.addFocusListener(this);

        st.setEditable(true);
        c.setEditable(true);

        setupBasicPanel();

    }

    private void setupBasicPanel() {
        removeAll();

        int y = 0;


        GridBagUtil.constrain(this, _cnLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, cn, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _oLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, o, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _ouLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, ou, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _lLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, l, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _stLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, statePanel, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _cLabel, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                0, 0, DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(this, c, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);


        GridBagUtil.constrain(this, Box.createVerticalGlue(),
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);


        GridBagUtil.constrain(this, m_showDNButton,
                              1, ++y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              0, 0, 0, 0);


    }

    /*public String getDN() {
	setDN();
	return dn.getText();
    }*/

    void setDN() {
        if (!dnModified) {
            dn.setText("");
            if (cn.getText().length() > 0) {
                dn.append("CN=\""+cn.getText()+"\"");
            }
            if (ou.getText().length() > 0) {
                dn.append((dn.getText().length()>0?", ":"")+"OU=\""+ou.getText()+"\"");
            }
            if (o.getText().length() > 0) {
                dn.append((dn.getText().length()>0?", ":"")+"O=\""+o.getText()+"\"");
            }
            if (l.getText().length() > 0) {
                dn.append((dn.getText().length()>0?", ":"")+"L=\""+l.getText()+"\"");
            }
            if ((st.getSelectedItem() != null) &&  (((String)(st.getSelectedItem())).length() > 0)){
                dn.append((dn.getText().length()>0?", ":"")+"ST=\""+st.getSelectedItem()+"\"");
            }

            if ((c.getSelectedItem() != null) && (((String)(c.getSelectedItem())).length() > 0)) {
                dn.append((dn.getText().length()>0?", ":"")+"C=\""+((String)(c.getSelectedItem())).substring(0,2)+"\"");
            }
        }
    }

    private void setupAdvancedPanel() {
        removeAll();

        int y = 0;

        GridBagUtil.constrain(this, dnWarning,
                              0, ++y, 2, 1,
                              0.0, 0.0, 
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, dnScrollPane,
                              0, ++y, 2, 1,
                              1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, m_showDNButton,
                              1, ++y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              0, 0, COMPONENT_SPACE, 0);

	setDN();

    }

    /*public static void main(String arg[]) {
        JFrame f = new JFrame();
	JDialog d = new JDialog(f, "", true);
	CertRequestInfoPage c = new CertRequestInfoPage(new Hashtable());
        d.getContentPane().add("North", c);
        d.setSize(400,400);
        d.show();

	//System.out.println(c.getDN());

	System.exit(0);
    }*/
}
