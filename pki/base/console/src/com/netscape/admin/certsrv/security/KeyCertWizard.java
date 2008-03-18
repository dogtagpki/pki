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
package com.netscape.admin.certsrv.security;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.io.*;

import javax.swing.*;

import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.console.ConsoleInfo;
import netscape.ldap.*;

import com.netscape.management.client.util.*;

/**
 *
 * Key and certificate setup wizard
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class KeyCertWizard {

    final int FIRSTPAGE = 0;

    WizardObservable wizardObservable;
    IWizardControl owner;
    Wizard wizard;

    Vector pages;
    int thisPage = 0;

    ConsoleInfo _consoleInfo;

    ResourceSet resource;
    Help help;

    void init(ConsoleInfo consoleInfo, String certName) {
        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.WAIT_CURSOR));

        resource = KeyCertUtility.getKeyCertWizardResourceSet();
        help = new Help(resource);

        wizardObservable = new WizardObservable(consoleInfo);
        _consoleInfo = consoleInfo;

        pages = new Vector();
        pages.addElement(new GuideIntroPane());
        //((IKeyCertPage)(pages.elementAt(thisPage))).pageShow(wizardObservable);
        pages.addElement(new CertRequestSelectTokenPane());
        pages.addElement(new GuideCreateTrustPane());
        pages.addElement(new CreateTrustPane());
        StatusPane statusPane = new StatusPane();
        pages.addElement(statusPane);
        pages.addElement(new GuideCertRequestPane());
        pages.addElement(new CertRequestTypePane());
        pages.addElement(new CertRequestInfoPane());
        pages.addElement(new CertRequestEnterPasswordPane());
        pages.addElement(statusPane);
        pages.addElement(new CertRequestCertPane());
        pages.addElement(new GuideCertInstallPane());
        pages.addElement(new CertInstallTypePane());
        pages.addElement(new CertInstallCertPane());
        pages.addElement(statusPane);
        pages.addElement(new CertInstallCertInfoPane());
        pages.addElement(statusPane);

        wizardObservable.put("statusPane", statusPane);

        try {
            wizard = new Wizard(null,
                    resource.getString("KeyCertWizard", "title"),
                    new WizardControlListener());
        } catch (Exception e) {
            wizard = new Wizard(null, "", new WizardControlListener());
        }

        if ((certName == null) || (certName.length() == 0)) {
            wizardObservable.put("certName", "Server-Cert");
        } else {
            wizardObservable.put("certName", certName);
        }

        wizard.setMinimumSize(425, 425);
        wizard.start();
    }


    /**
      * Create a key and certificate setup wizard
      *
      * @param consoleInfo
      *
      */
    public KeyCertWizard(ConsoleInfo consoleInfo, String certName) {
        super();
        init(consoleInfo, certName);
    }

    /**
      * Create a key and certificate setup wizard
      *
      *
      *
      */
    public KeyCertWizard(ConsoleInfo consoleInfo) {
        super();
        init(consoleInfo, null);
    }


    class WizardControlListener implements IWizardPageControl {
        public JPanel getCurrentPage() {
            try {
                return ( (IKeyCertPage)(pages.elementAt(thisPage))).
                        getPanel();
            } catch (Exception e) {
                return new JPanel();
            }
        }

        public JPanel getNextPage() {
            IKeyCertPage ipage = (IKeyCertPage)(pages.elementAt(thisPage));
            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.WAIT_CURSOR));
            try {
                if (!(ipage.pageHide(wizardObservable))) {
                    //check to see if we need to display some error message
                    //from cgi
                } else {



                    while (true) {
                        ipage = (IKeyCertPage)(pages.elementAt(++thisPage));
                        if (ipage.pageShow(wizardObservable)) {
                            break;
                        }
                    }
                    if ((ipage instanceof StatusPane) &&
                            ((StatusPane) ipage).hasError()) {
                        owner.setCanGoForward(false);
                    }

                    //-2 because we don't want to count the last status page as one of the normal
                    //page.  Also it's only managed by the certinfo page.
                    if (thisPage == (pages.size() - 2)) {
                        //owner.setIsLastPage(true);
                        owner.setCanGoForward(false);
                    } else if (thisPage == (pages.size() - 1)) {
                        owner.setCanGoForward(true);
                        owner.setIsLastPage(true);
                    }

                    owner.setCanGoBackword(true);

                }
            }
            catch (Exception e) {
                Debug.println(e + ":next page");
            }

            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.DEFAULT_CURSOR));
            return ipage.getPanel();
        }


        public JPanel getPrevPage() {
            IKeyCertPage page = null;
            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.WAIT_CURSOR));
            try {
                while (true) {
                    page = (IKeyCertPage)(pages.elementAt(--thisPage));
                    if ((page != null) && page.pageShow(wizardObservable)) {
                        break;
                    }
                }

                owner.setIsLastPage(false);
                owner.setCanGoForward(true);

                if (thisPage == FIRSTPAGE) {
                    owner.setCanGoBackword(false);
                }

                if (thisPage == ((pages.size()) - 1)) {
                    owner.setIsLastPage(true);
                } else if (thisPage == (pages.size() - 2)) {
                    owner.setCanGoForward(false);
                }
            } catch (Exception e) {
                Debug.println(e + ":prev page");
            }

            UtilConsoleGlobals.getActivatedFrame().setCursor(
                    new Cursor(Cursor.DEFAULT_CURSOR));
            return page.getPanel();
        }


        public void wizardCompleted() {
            //do clean up
            cleanUp();
        }
        public void wizardCanceled() {
            //do clean up
            cleanUp();
        }

        public void cleanUp() {
            wizardObservable = null;
            owner = null;
            wizard = null;

            pages = null;

            _consoleInfo = null;

            help = null;
        }

        public void helpInvoked() {
            Object currentPage = pages.elementAt(thisPage);
            if (currentPage instanceof GuideIntroPane) {
                help.help("GuideIntroPane", "help");
            } else if (currentPage instanceof CertRequestSelectTokenPane) {
                help.help("SelectToken", "help");
            } else if (currentPage instanceof GuideCreateTrustPane) {
                help.help("GuideCreateTrustPane", "help");
            } else if (currentPage instanceof CreateTrustPane) {
                help.help("CreateTrustPane", "help");
            } else if ((currentPage instanceof StatusPane) &&
                    (pages.elementAt(thisPage -
                    1) instanceof CreateTrustPane)) {
                help.help("CreateTrustPane", "help");
            } else if (currentPage instanceof GuideCertRequestPane) {
                help.help("GuideCertRequestPane", "help");
            } else if (
                    currentPage instanceof CertRequestEnterPasswordPane) {
                help.help("CertRequestEnterPasswordPane", "help");
            } else if (currentPage instanceof CertRequestTypePane) {
                help.help("CertRequestTypePane", "help");
            } else if ((currentPage instanceof StatusPane) &&
                    (pages.elementAt(thisPage -
                    1) instanceof CertRequestTypePane)) {
                help.help("CertRequestTypePane", "help");
            } else if (currentPage instanceof CertRequestInfoPane) {
                help.help("CertRequestInfoPane", "help");
            } else if (currentPage instanceof CertRequestCertPane) {
                help.help("CertRequestCertPane", "help");
            } else if (currentPage instanceof GuideCertInstallPane) {
                help.help("GuideCertInstallPane", "help");
            } else if (currentPage instanceof CertInstallTypePane) {
                help.help("CertInstallTypePane", "help");
            } else if (currentPage instanceof CertInstallCertPane) {
                help.help("CertInstallCertPane", "help");
            } else if ((currentPage instanceof StatusPane) &&
                    (pages.elementAt(thisPage -
                    1) instanceof CertInstallCertPane)) {
                help.help("CertInstallCertPane", "help");
            } else if (currentPage instanceof CertInstallCertInfoPane) {
                help.help("CertInstallCertInfoPane", "help");
            } else if ((currentPage instanceof StatusPane) &&
                    (pages.elementAt(thisPage -
                    1) instanceof CertInstallCertInfoPane)) {
                help.help("CertInstallCertInfoPane", "help");
            }
        }

        public void setOwner(IWizardControl wizardControl) {
            wizardObservable.put("Wizard", wizardControl);

            owner = wizardControl;
        }
    }


    /*public static void main(String arg[]) {
         JFrame f = new JFrame();
         ConsoleInfo consoleInfo = null;
         UtilConsoleGlobals.setActivatedFrame(f);
         f.setSize(400,400);

     try {
      UIManager.setLookAndFeel("javax.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

         f.show();
         String host = "buddha";
         try {
             consoleInfo = new ConsoleInfo(host+".mcom.com", 389, "admin", "admin", "o=airius.com");
             LDAPConnection connection = new LDAPConnection();
             consoleInfo.setAdminURL("https://"+host+".mcom.com:8081/");
             consoleInfo.setBaseDN("cn=admin-serv-"+host+", ou=Netscape SuiteSpot, o=Airius.com");
             consoleInfo.setCurrentDN("cn=admin-serv-"+host+", ou=Netscape SuiteSpot, o=Airius.com");
         } catch (Exception e) {System.out.println(e);}


         KeyCertWizard kc = new KeyCertWizard(consoleInfo);

         // f.setIconImage((new RemoteImage("com/netscape/management/client/images/AdminServer.gif")).getImage());
         //f.show();
     }*/
}
