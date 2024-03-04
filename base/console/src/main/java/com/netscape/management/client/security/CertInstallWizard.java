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

import java.awt.*;
import java.util.*;
import java.net.*;
import javax.swing.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.AdmTask;

/**
 * Certificate install wizard.
 * 
 * Certificate install wizard will guide user through the process
 * to install certificate.
 *
 * for design detail see: http://kingpin/console/4.5/security/install.htm
 * 
 * @see com.netscape.management.client.security.CertInstallWizard
 */
public class CertInstallWizard  {

    Wizard wizardDialog;
    IWizardSequenceManager sequenceManager = new WizardSequenceManager();
    IDataCollectionModel dataCollectionModel = new WizardDataCollectionModel();

    /* certificate to be install is a server certificate */
    public static int SERVER = 0;
    /* certificate to be install is a ca certificate */
    public static int CA     = 1;

    class TokenPwdPage extends WizardPage {
        TokenPasswordPage pwdPage;
        public TokenPwdPage() {
            super(KeyCertUtility.getResourceSet().getString("TokenPasswordPage", "pageTitle"));
            pwdPage = new TokenPasswordPage(dataCollectionModel);
	    
            setLayout(new GridBagLayout());

            GridBagUtil.constrain(this,
                                  pwdPage,
                                  0, 0, 1, 1,
                                  1.0, 1.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                                  0, 0, 0, 0);
        }

        public boolean canMoveForward() {
            return pwdPage.isPageValidated();
        }

        public void helpInvoked() {
            KeyCertUtility.getHelp().contextHelp("TokenPasswordPage", "help");
        }


        public boolean nextInvoked() {
            boolean canProceed = false;
            //install cert here
            try {
                wizardDialog.setBusyCursor(true);
                
                Hashtable args = new Hashtable();
                args.put("formop", "INSTALL_CERT");

                //if installmethod is any none null value
                //then the cgi will attempt to add cert.
                args.put("installmethod", "1");

                args.put("sie"      , dataCollectionModel.getValue("sie"));
                args.put("tokenname", dataCollectionModel.getValue("tokenname"));
                args.put("dercert"  , dataCollectionModel.getValue("dercert"));
                args.put("certtype" , dataCollectionModel.getValue("certtype"));
                args.put("keypwd"   , dataCollectionModel.getValue("keypwd"));
                args.put("certname" , dataCollectionModel.getValue("certname"));
                args.put("trust_flag", "0");

                //this number matches what is defined under NSS.
                //this might be a bad idea, but parsing string on both cgi
                //and console code might not be a good idea either
                //static int TRUSTED_CA       = 16;
                //static int TRUSTED_CLIENT_CA  = 128;

                ConsoleInfo consoleInfo = (ConsoleInfo)(dataCollectionModel.getValue("consoleInfo"));

                AdmTask admTask = new AdmTask(new URL(consoleInfo.getAdminURL() +
                                                      "admin-serv/tasks/configuration/SecurityOp"),
                                              consoleInfo.getAuthenticationDN(),
                                              consoleInfo.getAuthenticationPassword());

                admTask.setArguments(args);

                admTask.exec();
                Debug.println(admTask.getResultString().toString());
                //System.out.println(admTask.getResultString());


                if (!SecurityUtil.showError(admTask)) {
                    dataCollectionModel.setValue("certlist", new CertificateList(admTask.getResultString().toString()));
                    canProceed = true;
                }
            } catch (Exception e) {
                SecurityUtil.printException("CertInstallWizard::nextInvoked()",e);
            }
            finally {
                wizardDialog.setBusyCursor(false);
            }

            return canProceed;
        }
    }

    public CertInstallWizard(Component parent, 
                             ConsoleInfo consoleInfo, 
                             String sie, 
                             String tokenName,
                             int certType,
                             String certName,
                             Vector installedServerCerts) {

        Dialog owner = (Dialog)SwingUtilities.getAncestorOfClass(Dialog.class, parent);	
        wizardDialog = new Wizard(owner,
                                  KeyCertUtility.getResourceSet().getString("CertInstallWizard", "title"),
                                  true, 
                                  sequenceManager,
                                  dataCollectionModel);

        dataCollectionModel.setValue("tokenname"  , tokenName);
        dataCollectionModel.setValue("sie"        , sie.toLowerCase());
        dataCollectionModel.setValue("consoleInfo", consoleInfo);
        dataCollectionModel.setValue("certtype"   , Integer.toString(certType));

        if (certName.length()>0) {
            dataCollectionModel.setValue("certname", certName);
        }

        if (installedServerCerts != null) {
            dataCollectionModel.setValue("installedServerCerts", installedServerCerts);
        }

        try {
            wizardDialog.addPage("CertInstallCertPage", new CertInstallCertPage(consoleInfo));
            wizardDialog.addPage("CertInstallCertInfoPage", new CertInstallCertInfoPage());
            wizardDialog.addPage("CertInstallCertNamePage", new CertInstallCertNamePage(tokenName, sie, consoleInfo));
            if (certType == SERVER) {
                wizardDialog.addPage("TrustDBPasswordPage", new TokenPwdPage());

            } else if (certType == CA) {
                //trust page here
                wizardDialog.addPage("CertInstallSetTrustPage", new CertInstallSetTrustPage());
            }
        } catch (Exception e) {
            SecurityUtil.printException("CertInstallWizard::CertInstallWizard(...)",e);
        }

        wizardDialog.setSize(500, 350);

        if (!(parent instanceof Frame)) {
            ModalDialogUtil.setDialogLocation(wizardDialog,parent);
        }
    }


    /**
     * Create a instance of the certifificate request wizard.
     *
     * ***WARNING***
     * This wizard use a plugin model, it assume there is a ./caplugin directory
     * on where this wizard is lunched.  under that directory it must contain a 
     * "default.jar" which provide manual cert request ui.
     * ***WARNING***
     *
     * to implement your own plugin see: http://kingpin/console/4.5/security/ca.htm
     *
     * @param parent component from where this wizard was lunched
     * @param consoleInfo information required for this wizard to contact admin server inorder to generate key pair and CSR
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     * @param tokenName token to use, key pair will be generated using the token specified, and token is also where the cert will probably be install to.
     * @param certType specify the certificate type.  possible value CertInstallWizard.SERVER or CertInstallWizard.CA
     *
     * @see com.netscape.management.client.security.CertRequestWizard
     */
    public CertInstallWizard(Component parent, 
                             ConsoleInfo consoleInfo, 
                             String sie, 
                             String tokenName,
                             int certType,
                             Vector installedServerCerts) {
        this(parent, consoleInfo, sie, tokenName, certType, "", installedServerCerts);
    }

    /**
     * Show or hide certificate request wizard
     *
     * @param visible if true wizard will be lunched
     */
    public void setVisible(boolean visible) {
        wizardDialog.setVisible(visible);
    }

    /*public static void main(String arg[]) {
      JFrame f = new JFrame();
      CertInstallWizard w = new CertInstallWizard(f);
      w.setVisible(true);
      }*/
}
