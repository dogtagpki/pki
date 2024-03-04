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
package com.netscape.management.client.security;


import java.util.*;
import java.text.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.tree.*;

//import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


class CertificateInfoPanels implements SuiConstants {

    ResourceSet resource;
    Hashtable _cert;
    Border defaultBorder;
    int top = UIConstants.VERT_WINDOW_INSET, left = UIConstants.HORIZ_WINDOW_INSET, bottom = UIConstants.VERT_WINDOW_INSET, right = UIConstants.HORIZ_WINDOW_INSET;

    JLabel getBoldAlignLabel(String labelString, int align) {
	JLabel label = new JLabel(labelString, align);
	Font font = label.getFont();
	label.setFont(new Font(font.getName(), font.getStyle() | Font.BOLD, font.getSize()));

	return label;
    }

    JLabel getBoldRightAlignLabel(String labelString) {
	return getBoldAlignLabel(labelString, JLabel.RIGHT);
    }

    JLabel getBoldLabel(String labelString) {
	return getBoldAlignLabel(labelString, JLabel.LEFT);
    }



    /**
      * Certificate chain tree cell render, all node should have same icon
      *
      *
      */
    class CertTreeCellRenderer extends SuiTreeCellRenderer {
        public CertTreeCellRenderer() {
            super();
/*            leafIcon = new RemoteImage(
                    _resource.getString("ViewCertificateDialog", "certImage"));
            closedIcon = leafIcon;
            openIcon = leafIcon;*/
        }
    }

    private String convertNullString(Object str) {
	if (str.toString().equals("(null)")) {
	    return resource.getString("CertificateDetailDialog", "invalidFQDN");
	}
	return str.toString();
    }
    /**
      * Construct a certificate chain tree
      * @param certs  certificate chain
      *
      */
    public JComponent getCertChainInfo() {
	Hashtable certChainHash = (Hashtable)(_cert.get("CERT_CHAIN"));


        /* get certificate icon */
        /*RemoteImage chainIcon = new RemoteImage(
                _resource.getString("ViewCertificateDialog", "chainImage"));*/

        /* setup tree data*/
	DefaultMutableTreeNode top = new DefaultMutableTreeNode(convertNullString(certChainHash.get("CERT"+Integer.toString(certChainHash.size()-1))));

        DefaultMutableTreeNode parent = top;
        DefaultMutableTreeNode child;

        for (int i = certChainHash.size()-2; i >= 0 ; i--) {
            child = new DefaultMutableTreeNode(convertNullString(certChainHash.get("CERT"+i)));

            parent.add(child);
            parent = child;
        }

        /* create a tree that can't be collapsed */
        final JTree certChain = new JTree(top) {
                    public void processMouseEvent(MouseEvent e) {
                        int selRow = getRowForLocation(e.getX(), e.getY());
                        if ((selRow != -1) && (e.getClickCount() == 1)) {
                            setSelectionRow(selRow);
                        }
                    }
                };

        certChain.setCellRenderer(new CertTreeCellRenderer());


        /* expand all the node, and set server certificate to be visible */
        for (int i = 0; i <= certChainHash.size(); i++) {
            certChain.expandRow(i);
        }
        certChain.setSelectionRow(certChainHash.size() - 1);
        certChain.scrollRowToVisible(certChainHash.size() - 1);

        //Listen for when the selection changes.
        certChain.addTreeSelectionListener(new TreeSelectionListener() {
                    public void valueChanged(TreeSelectionEvent e) {
                        DefaultMutableTreeNode node =
                                (DefaultMutableTreeNode)
                                (e.getPath().getLastPathComponent());
                        Object nodeInfo = node.getUserObject();
                        /*certInfoView.setBottomComponent(
                                setupDetailInfoPane(
                                ((CertNode) nodeInfo).getX509Cert()));
                        certInfoView.validate();
                        certInfoView.repaint();*/
                    }
                }
                );


        /*JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(2, 2, 0, 0));
        p.setBackground(UIManager.getColor("window"));
        p.add(certChain);*/

        JScrollPane _treePanel = new JScrollPane();
        _treePanel.getViewport().add(certChain);
        _treePanel.setPreferredSize(new Dimension(125, 75));
        _treePanel.setMinimumSize(new Dimension(1, 1));
        _treePanel.setBorder(defaultBorder);

        return setInset(_treePanel);
    }

    JPanel getGeneralInfo() {
	JPanel generalInfoPane = new JPanel();
	generalInfoPane.setLayout(new GridBagLayout());
        generalInfoPane.setBorder(defaultBorder);

	generalInfoPane.setBackground(Color.white);
	
	JLabel issuedToLabel  = getBoldRightAlignLabel(resource.getString("CertificateDetailDialog", "issuedTo"));
	JLabel issuedByLabel  = getBoldRightAlignLabel(resource.getString("CertificateDetailDialog", "issuedBy"));
	JLabel serialNumLabel = getBoldRightAlignLabel(resource.getString("CertificateDetailDialog", "serialNum"));
	JLabel fingerprintLabel = getBoldRightAlignLabel(resource.getString("CertificateDetailDialog", "fingerprint"));
	JLabel intendedLabel = getBoldLabel(resource.getString("CertificateDetailDialog", "intendedTo"));

	int y =0;
	GridBagUtil.constrain(generalInfoPane, issuedToLabel,
                              0, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              VERT_WINDOW_INSET, COMPONENT_SPACE, 0, 0);

	String certCN = (String)(((Hashtable)(_cert.get("SUBJECT"))).get("CN"));
	JLabel issuedTo = new JLabel(certCN.equals("(null)")?"":certCN);
	issuedToLabel.setLabelFor(issuedTo);
	GridBagUtil.constrain(generalInfoPane, issuedTo,
                              1, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              VERT_WINDOW_INSET, COMPONENT_SPACE, 0, COMPONENT_SPACE);

	GridBagUtil.constrain(generalInfoPane, issuedByLabel,
                              0, ++y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);

	certCN = (String)(((Hashtable)(_cert.get("ISSUER"))).get("CN"));
	JLabel issuedBy = new JLabel(certCN.equals("(null)")?"":certCN);
	issuedByLabel.setLabelFor(issuedBy);
	GridBagUtil.constrain(generalInfoPane, issuedBy,
                              1, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);

	GridBagUtil.constrain(generalInfoPane, serialNumLabel,
                              0, ++y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);

	JLabel serialNum = new JLabel((String)(_cert.get("SERIAL")));
	serialNumLabel.setLabelFor(serialNum);
	GridBagUtil.constrain(generalInfoPane, serialNum,
                              1, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);

	GridBagUtil.constrain(generalInfoPane, fingerprintLabel,
                              0, ++y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);
	
	JLabel fingerprint = new JLabel((String)(_cert.get("FINGERPRINT")));
	fingerprintLabel.setLabelFor(fingerprint);
	GridBagUtil.constrain(generalInfoPane, fingerprint,
                              1, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);

	



	try{

	    String dateFormat = resource.getString("CertificateDetailDialog", "dateFormat");

	    SimpleDateFormat formatter = new SimpleDateFormat ("EEE MMM dd HH:mm:ss yyyy");

	    //set date
	    GregorianCalendar f = new GregorianCalendar();
	    f.setTime(formatter.parse((String)(_cert.get("BEFOREDATE"))));

	    GregorianCalendar t = new GregorianCalendar();
	    t.setTime(formatter.parse((String)(_cert.get("AFTERDATE"))));

	    String from = KeyCertUtility.replace( KeyCertUtility.replace( KeyCertUtility.replace(dateFormat, "%Y%",
                Integer.toString(f.get(Calendar.YEAR))), "%M%",
                Integer.toString(f.get(Calendar.MONTH) + 1)), "%D%",
                Integer.toString(f.get(Calendar.DATE)));

	    String to = KeyCertUtility.replace( KeyCertUtility.replace( KeyCertUtility.replace(dateFormat, "%Y%",
                Integer.toString(t.get(Calendar.YEAR))), "%M%",
                Integer.toString(t.get(Calendar.MONTH) + 1)), "%D%",
                Integer.toString(t.get(Calendar.DATE)));


	    JPanel datePanel = new JPanel();
	    datePanel.setLayout(new GridBagLayout());
	    datePanel.setBackground(generalInfoPane.getBackground());

	    int x = -1;
	    StringTokenizer st = new StringTokenizer(
		resource.getString("CertificateDetailDialog", "valid"), " ", false);

	    while (st.hasMoreTokens()) {
		String token = (String)(st.nextElement());
		Component c = null;
		if (token.equals("%AFTERDATE%")) {
		    c = new JLabel(from);
		} else if (token.equals("%BEFOREDATE%")) {
		    c = new JLabel(to);
		} else {
		    c = getBoldLabel(resource.getString("CertificateDetailDialog", token));
		}

		int space = 0;

		if (token.equals("%AFTERDATE%") || token.equals("%BEFOREDATE%")) {
		    space = COMPONENT_SPACE;
		}


		GridBagUtil.constrain(datePanel, c, ++x, 0, 1, 1, 0.0, 0.0,
                    GridBagConstraints.WEST, GridBagConstraints.NONE,
                    0, space, 0, space);
	    }

	    GridBagUtil.constrain(datePanel, Box.createHorizontalGlue(), ++x, 0, 1, 1, 1.0, 0.0,
                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                    0, 0, 0, 0);

	    //valid from valid to
	    GridBagUtil.constrain(generalInfoPane, datePanel,
				  0, ++y, 2, 1,
				  1.0, 0.0,
				  GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
				  COMPONENT_SPACE, 18, 0, COMPONENT_SPACE);
	} catch (Exception e) {
	    SecurityUtil.printException("CertificateInfoPanels::getGeneralInfo()",e);
	    Debug.println("Fail to parse certificate validation date.");
	    Debug.println("AFTERDATE : "+_cert.get("AFTERDATE"));
	    Debug.println("BEFOREDATE: "+_cert.get("BEFOREDATE"));
	}



        //the intended purpose of the certificate
	Hashtable purpose = (Hashtable)(_cert.get("PURPOSE"));
        if (purpose != null) {
            GridBagUtil.constrain(generalInfoPane, intendedLabel,
                                  0, ++y, 2, 1,
                                  1.0, 0.0,
                                  GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                                  COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
            Enumeration keys = purpose.keys();
            while (keys.hasMoreElements()) {
              String labelString = keys.nextElement().toString();
              if (labelString.equals("SSLClient")) {
                  labelString = resource.getString("CertificateDetailDialog", "sslclient");
              } else if (labelString.equals("SSLServer")) {
		  labelString = resource.getString("CertificateDetailDialog", "sslserver");
              } else if (labelString.equals("SSLCA")) {
		  labelString = resource.getString("CertificateDetailDialog", "sslca");
              } else if (labelString.equals("EmailSigner")) {
		  labelString = resource.getString("CertificateDetailDialog", "emailsigner");
              } else if (labelString.equals("EmailRecipient")) {
		  labelString = resource.getString("CertificateDetailDialog", "emailrecipient");
              } else if (labelString.equals("ObjectSigner")) {
		  labelString = resource.getString("CertificateDetailDialog", "objectsigner");
              }
              
	      JLabel intended = new JLabel(labelString);
	      intendedLabel.setLabelFor(intended);
              GridBagUtil.constrain(generalInfoPane, intended,
                                    0, ++y, 2, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                                    COMPONENT_SPACE, COMPONENT_SPACE*5, 0, COMPONENT_SPACE);
	    
            }
        }

        //reason for trusting this certificate
        Hashtable reasons = (Hashtable)(_cert.get("REASONS"));
        if (reasons != null) {
            GridBagUtil.constrain(generalInfoPane, intendedLabel,
                                  0, ++y, 2, 1,
                                  1.0, 0.0,
                                  GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                                  COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
            Enumeration keys = reasons.keys();
            while (keys.hasMoreElements()) {
              String labelString = reasons.get(keys.nextElement()).toString();
              GridBagUtil.constrain(generalInfoPane, new JLabel(labelString),
                                    0, ++y, 2, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                                    COMPONENT_SPACE, COMPONENT_SPACE*5, 0, COMPONENT_SPACE);
            }
        }

	GridBagUtil.constrain(generalInfoPane, Box.createVerticalGlue(),
                              0, ++y, 1, 1,
                              0.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.VERTICAL,
                              0, 0, 0, 0);


	return setInset(generalInfoPane);
    }


     /**
      * Create a vector that contain 2 elements (key, value) and add it
      * to a vector
      */
    private void setRowValue(Vector rowData, String field, Object value) {
        if ((value != null) && 
	    (value.toString().length() != 0) &&
	    !(value.toString().equals("(null)"))) {
            Vector v = new Vector();
            v.addElement(field);
            v.addElement(value);

            rowData.addElement(v);
        }
    }

    JComponent getDetailInfo() {
	JPanel detailInfoPane = new JPanel();

        Vector columnNames = new Vector();
        columnNames.addElement(
                resource.getString("CertificateDetailDialog", "fieldTitle"));
        columnNames.addElement(
                resource.getString("CertificateDetailDialog", "valueTitle"));

	Hashtable subject = (Hashtable)(_cert.get("SUBJECT"));
	//crl/ckl don't have subject
	if (subject == null) {
	    subject = new Hashtable();
	}
	Hashtable issuer = (Hashtable)(_cert.get("ISSUER"));

        Vector rowData = new Vector();
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "subject"),
		    subject.get("CN"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "issuer"), 
		    issuer.get("CN"));
        setRowValue(rowData,
                resource.getString("CertificateDetailDialog", "validFrom"), 
		    _cert.get("BEFOREDATE"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "validTo"), 
		    _cert.get("AFTERDATE"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "email"), 
		    subject.get("EMAIL"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "locality"), 
		    subject.get("L"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "org"),
		    subject.get("O"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "orgUnit"), 
		    subject.get("OU"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "state"),
		    subject.get("ST"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "country"), 
		    subject.get("C"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "fingerprint"),
		    _cert.get("FINGERPRINT"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "signature"),
		    _cert.get("SIGNATURE"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "algorithm"),
		    _cert.get("ALGORITHM"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "keystrength"),
		    _cert.get("KEYSTRENGTH"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "version"),
		    _cert.get("VERSION"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "serial"),
		    _cert.get("SERIAL"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "subjectDN"),
		    _cert.get("SUBJECT_DN"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "issuerDN"),
		    _cert.get("ISSUER_DN"));

	//apply only to crl/ckl
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "effectiveDate"),
		    _cert.get("LAST_UPDATE"));
        setRowValue(rowData,
		    resource.getString("CertificateDetailDialog", "nextUpdate"),
		    _cert.get("NEXT_UPDATE"));
	//if there is more info add here
	//make sure to add the localized version of the 
	//field name under the properties file.


	Table _table = new Table(new ListTableModel(columnNames, rowData));
	JScrollPane sp = Table.createScrollPaneForTable(_table);

        return setInset(sp);
    }

    /* shouldn't be calling this function unless you are dealing with crl/ckl */
    public JComponent getRevocationList() {
        Vector columnNames = new Vector();
        columnNames.addElement(
                resource.getString("CertificateDetailDialog", "serial"));
        columnNames.addElement(
                resource.getString("CertificateDetailDialog", "revocationDate"));

        Vector rowData = new Vector();

	int i = 0;
	while (true) {
	    Hashtable entry = (Hashtable)(_cert.get("ENTRY"+i));
	    if (entry != null) {
		try {
		    setRowValue(rowData,
				(String)(entry.get("SERIAL_NUMBER")),
				(String)(entry.get("REVOKE_DATE")));
		} catch (Exception e) {
		    //display an error message.  For some reason my 
		    //return string contain some extra junk characters 
		    //when the list gets to be too long.
		    //the valid senrio is to make sure backend don't return
		    //junks...instead of putting a hack here.
		    //something is goofy about stdout at the backend.
		}
		i++;
	    } else {
		break;
	    }
	}

	Table _table = new Table(new ListTableModel(columnNames, rowData));
	JScrollPane sp = Table.createScrollPaneForTable(_table);

        return setInset(sp);
    }

    private JPanel setInset(Component c) {
        JPanel p = new JPanel();
	p.setLayout(new GridBagLayout());

	GridBagUtil.constrain(p, c,
                              0, 0, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              top, left, bottom, right);
	return p;
    }

    /*JPanel getChainInfo(Vector certList) {
    }*/
    public void setInset(int top, int left, int bottom, int right) {
        this.top = top;
	this.left = left;
	this.bottom = bottom;
	this.right = right;
    }

    public CertificateInfoPanels(Hashtable cert) {
        resource = new ResourceSet("com.netscape.management.client.security.securityResource");

	_cert = cert;

	/*defaultBorder = new MatteBorder(DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, Color.gray);*/
	defaultBorder = BorderFactory.createLoweredBevelBorder();

	/*defaultBorder = new CompoundBorder(
                new MatteBorder(DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, Color.gray),
                new BevelBorder(BevelBorder.LOWERED, Color.white,
                Color.gray, Color.black, Color.black));*/
    }

}
