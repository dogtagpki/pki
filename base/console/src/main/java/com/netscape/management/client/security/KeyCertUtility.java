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

import com.netscape.management.nmclf.*;
import java.util.*;
import java.net.*;
import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;

//import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleInfo;



class KeyCertUtility {



    static ResourceSet _resource = null;
    public static ResourceSet getResourceSet() {
        if (_resource == null) {
            _resource = new ResourceSet("com.netscape.management.client.security.KeyCertWizardResource");

        }

        return _resource;
    }

    static ResourceSet _resource_theme = null;
    public static ResourceSet getResourceSetTheme() {
        if (_resource_theme == null) {
            _resource_theme = new ResourceSet("com.netscape.management.client.theme.theme");

        }

        return _resource_theme;
    }

    static Help _help = null;
    public static Help getHelp() {
        if (_help == null) {
            _help = new Help(_resource);
        }

        return _help;
    }


    //replace any occurance of 'val' in 'oldStr' with 'replacement'
    public static String replace(String oldStr, String val,
            String replacement) {
        String output = new String(oldStr);

        int index;

        while ((index = output.indexOf(val)) != -1) {
            output = output.substring(0, index) + replacement +
                    output.substring(index + val.length());
        }

        return output;
    }

    public static String getCertName(Hashtable cert) {
        return getCertName(cert, null, null, null);
    }

    public static String getCertName(Hashtable cert, String tokenName, ConsoleInfo consoleInfo, String sie) {
	String certname = "";

	if (cert == null) {
	    return certname;
	}

	Vector certs, conflictCerts = new Vector();
	int index = 2;

	Hashtable subject = (Hashtable)(cert.get("SUBJECT"));
	certname = (String)(subject.get("CN"));
	if (certname.equals("(null)")) {
	    certname = (String)(subject.get("OU"));
		if (certname.equals("(null)")) {
		    certname = (String)(subject.get("O"));
		}
	}

	if ( (tokenName != null) && (consoleInfo != null) ) {
		try {
			Hashtable args = new Hashtable();
			args.put("formop", "LIST_CERTIFICATE");
			args.put("sie", sie);
			args.put("tokenname", tokenName);
			AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
								"admin-serv/tasks/configuration/SecurityOp"),
								consoleInfo.getAuthenticationDN(),
								consoleInfo.getAuthenticationPassword());
			admTask.setArguments(args);
			admTask.exec();
			certs = new CertificateList(admTask.getResultString().toString()).getCerts();

			for (int i = 0; i < certs.size(); i++) {
				String tmpName = (String)((Hashtable)certs.elementAt(i)).get("NICKNAME");
				if (baseCertName(tmpName).equals(certname)) {
					int j = tmpName.indexOf(" #");

					if (j > 0 ) {
						int tmpIndex = Integer.parseInt(tmpName.substring(j + 2));

						if (tmpIndex >= index) {
							index = tmpIndex + 1;
						}
					}
					conflictCerts.add((String)((Hashtable)certs.elementAt(i)).get("FINGERPRINT"));
				}
			}

			if (conflictCerts.size() > 0) {
				args.put("formop", "FIND_CERTIFICATE");
				for (int i = 0; i < conflictCerts.size(); i++) {
// Treat matching subject DNs as renewal
					args.put("certfingerprint", conflictCerts.elementAt(i));
					admTask.setArguments(args);
					admTask.exec();
					Vector tmpCert = new CertificateList(admTask.getResultString().toString()).getCerts();
					String tmpSubject = (String)((Hashtable)tmpCert.elementAt(0)).get("SUBJECT_DN");
					if (tmpSubject.equals(cert.get("SUBJECT_DN"))) {
						return (String)((Hashtable)tmpCert.elementAt(0)).get("NICKNAME");
					}
				}
// No subjects matched so we have nickname collision, adding index to name
				return certname + " #" + index;
			}
		} catch (Exception e) {
			Debug.println(e.toString());
		}
	}
	return certname;
    }

    public static String baseCertName(String name) {
	int index = name.indexOf(" #");
		if (index > 0) {
			return name.substring(0, index);
		}
		else {
			return name;
		}
	}

    public static String getIssuerOrSubject(Hashtable cert){
	StringBuffer sb = new StringBuffer();
	String cn = (String)(cert.get("CN"));
	String o  = (String)(cert.get("O"));
	String ou = (String)(cert.get("OU"));
	String l  = (String)(cert.get("L"));
	String st = (String)(cert.get("ST"));
	String c  = (String)(cert.get("C"));
	if (!(cn.equals("(null)"))) {
	    sb.append(cn);
	}
	if (!(o.equals("(null)"))) {
	    sb.append(sb.length()>0?"\n":"");
	    sb.append(o);
	}
	if (!(ou.equals("(null)"))) {
	    sb.append(sb.length()>0?"\n":"");
	    sb.append(ou);
	}
	if (!(l.equals("(null)"))) {
	    sb.append(sb.length()>0?"\n":"");
	    sb.append(l);
	}
	if (!(st.equals("(null)"))) {
	    sb.append(sb.length()>0?"\n":"");
	    sb.append(st);
	}
	if (!(c.equals("(null)"))) {
	    sb.append(sb.length()>0?"\n":"");
	    sb.append(c);
	}

	return sb.toString();
    }	

    public static void getCert(Component parent,
				 ConsoleInfo consoleInfo, 
				 String sie, 
				 String certname, 
				 String fingerprint) {

	JPanel p = new JPanel();
	p.setLayout(new GridBagLayout());
	try {
	    Hashtable args = new Hashtable();
	    args.put("formop", "FIND_CERTIFICATE");
	    args.put("sie", sie);
	    args.put("certname", certname);
        args.put("certfingerprint", fingerprint);

	    AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());

	    admTask.setArguments(args);
	    admTask.exec();
	    Debug.println(admTask.getResultString().toString());

	    if (admTask.getStatus() != 0) {
		//display error
		Dialog dialog =(Dialog)SwingUtilities.getAncestorOfClass(AbstractDialog.class, parent);
		ErrorDialog errorDialog = new ErrorDialog(dialog,
						  (String)(admTask.getResult("NMC_ErrType")),
						  (String)(admTask.getResult("NMC_ErrDetail")));
		errorDialog.hideDetail();
		errorDialog.show();
		return;
	    }  else {
		CertificateList certList = new CertificateList(admTask.getResultString().toString());
		JPanel certP = null;
		if (certList.getCACerts().size()!=0) {
		    certP = createCertDetailInfo(((Hashtable)(certList.getCACerts().elementAt(0))));
		} else if (certList.getServerCerts().size() != 0) {
		    certP = createCertDetailInfo(((Hashtable)(certList.getServerCerts().elementAt(0))));
		}

		ResourceSet resource = getResourceSet();
		JLabel certNameLabel = new JLabel(resource.getString("CertInfoPage", "certNameLabel")+" "+certname);
		certNameLabel.setLabelFor(certP);
		GridBagUtil.constrain(p, certNameLabel,
				      0, 0, 1, 1,
				      1.0, 0.0,
				      GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
				      0, 0, 0, 0);

		JScrollPane scrollPane = new SuiScrollPane(certP);
		scrollPane.setBorder(new EmptyBorder(0,0,0,0));
		GridBagUtil.constrain(p, scrollPane/*certP*/,
				      0, 1, 1, 1,
				      1.0, 1.0,
				      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
				      0, 0, 0, 0);
	    }
	} catch (Exception e) {
	    Debug.println(e.toString());
	}

	Frame owner = (Frame)SwingUtilities.getAncestorOfClass(Frame.class, parent);
	AbstractDialog a = new AbstractDialog(owner, "", AbstractDialog.OK) {};
	a.setSize(400,300);
	a.getContentPane().add(p);
	a.setVisible(true);
	//return p;
    }

    public static boolean deleteCert(Component parent,
                                     ConsoleInfo consoleInfo,
                                     String sie,
                                     String certName,
                                     String fingerprint) {
	boolean success = true;	
	try {
	    Hashtable args = new Hashtable();
	    args.put("formop", "DELETE_CACERT");
	    args.put("sie", sie);
	    args.put("certname", certName);
        args.put("certfingerprint", fingerprint);                                     

	    AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
						  "admin-serv/tasks/configuration/SecurityOp"),
					  consoleInfo.getAuthenticationDN(),
					  consoleInfo.getAuthenticationPassword());

	    admTask.setArguments(args);
	    
	    //admTask.exec();
	    if (!SecurityUtil.execWithPwdInput(admTask, args, null)) {
	        success = false;
	    }
	    else if (admTask.getStatus() != 0) {
		//display error
		Dialog dialog = (Dialog)SwingUtilities.getAncestorOfClass(AbstractDialog.class, parent);
		ErrorDialog errorDialog = new ErrorDialog(dialog,
							  (String)(admTask.getResult("NMC_ErrType")),
							  (String)(admTask.getResult("NMC_ErrDetail")));
		errorDialog.hideDetail();
		errorDialog.show();

		success = false;
	    }
	} catch (Exception e) {
	    Debug.println(e.toString());
	}
	return success;
    }

    public static JPanel createCertDetailInfo(Hashtable cert) {
	JPanel p = new JPanel();
	p.setLayout(new GridBagLayout());

	StringBuffer sbLeft  = new StringBuffer();
	StringBuffer sbRight = new StringBuffer();

	ResourceSet resource = getResourceSet();

	sbLeft.append(resource.getString("CertInfoPage", "issuer"));
	sbLeft.append(KeyCertUtility.getIssuerOrSubject((Hashtable)(cert.get("ISSUER"))));
	sbLeft.append("\n\n");
	sbLeft.append(resource.getString("CertInfoPage", "subject"));
	sbLeft.append(KeyCertUtility.getIssuerOrSubject((Hashtable)(cert.get("SUBJECT"))));

	sbRight.append(resource.getString("CertInfoPage", "validAfter"));
	sbRight.append(cert.get("BEFOREDATE"));
	sbRight.append("\n\n");
	sbRight.append(resource.getString("CertInfoPage", "validBefore"));
	sbRight.append(cert.get("AFTERDATE"));
	sbRight.append("\n\n");
	sbRight.append(resource.getString("CertInfoPage", "fingerPrint"));
	sbRight.append(cert.get("FINGERPRINT"));
	sbRight.append("\n\n");
	sbRight.append(resource.getString("CertInfoPage", "serialNum"));
	sbRight.append(cert.get("SERIAL"));

	MultilineLabel leftLabel = new MultilineLabel(sbLeft.toString());
	MultilineLabel rightLabel = new MultilineLabel(sbRight.toString());

	GridBagUtil.constrain(p, leftLabel,
			      0, 0, 1, 1,
			      1.0, 1.0,
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
			      0, 0, 0, 0);

	GridBagUtil.constrain(p, rightLabel,
			      1, 0, 1, 1,
			      1.0, 1.0,
			      GridBagConstraints.NORTH, GridBagConstraints.BOTH,
			      0, 0, 0, 0);

	return p;
    }

    //a valid is a password that has more then 8 character and contain one or more
    //none alphabetic character
    /*public static boolean validPassword(String passwd,
            String confirmPasswd, ConsoleInfo consoleInfo) {
        boolean valid = true;
        if (!(passwd.equals(confirmPasswd))) {
            valid = false;
            SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                    getKeyCertWizardResourceSet().getString("KeyCertUtility",
                    "passwdMissMatch"));
            ModalDialogUtil.sleep();
        } else if (passwd.length() < 8) {
            valid = false;
            SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                    getKeyCertWizardResourceSet().getString("KeyCertUtility",
                    "lessThen8Char"));
            ModalDialogUtil.sleep();
        } else {
            boolean allChar = true;
            int length = confirmPasswd.length();
            for (int i = 0; i < length; i++) {
                char ch = confirmPasswd.charAt(i);
                if (!((ch >= 'A') && (ch <= 'Z')) &&
                        !((ch >= 'a') && (ch <= 'z'))) {
                    allChar = false;
                    break;
                }
            }
            if (allChar) {
                valid = false;
                SuiOptionPane.showMessageDialog(consoleInfo.getFrame(),
                        getKeyCertWizardResourceSet().getString("KeyCertUtility",
                        "noNumericChar"));
                ModalDialogUtil.sleep();
            }
        }

        return valid;
    }*/
}
