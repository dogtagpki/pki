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
import java.util.*;
import java.net.*;
import java.io.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.text.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.comm.HttpChannel;

class CertRequestCertPane extends JPanel implements SuiConstants,
IKeyCertPage {

    JTextArea certReq = new JTextArea(7, 10);
    JScrollPane scrollPane = new JScrollPane(certReq,
            JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
            JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    String explainEMail, explainURL;
    JButton copy;
    String oldUrl = "";



    public JPanel getPanel() {
        return this;
    }



    class CertPaneActionListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            if (event.getActionCommand().equals("COPY")) {
                certReq.selectAll();
                certReq.copy();
                certReq.setSelectionEnd(certReq.getSelectionEnd());
            }
        }
    }

    public boolean pageHide(WizardObservable observable) {
        return true;
    }

    public boolean pageShow(WizardObservable observable) {
        boolean show =
                ((Boolean)(observable.get("requestCert"))).booleanValue();


        Hashtable param = (Hashtable)(observable.get("CertReqCGIParam"));
        if (show && param.get("xmt_select").equals("1")) {

            Hashtable urlParam = new Hashtable();
            urlParam.put("op" , "submitCSR");
            urlParam.put("csrCertType" , "server");
            urlParam.put("csrRequestorName" , param.get("requestor_name"));
            urlParam.put("csrRequestorEmail" , param.get("email_address"));
            urlParam.put("csrRequestorPhone" , param.get("telephone"));
            urlParam.put("csrRequestorComments", "");
            urlParam.put("pkcs10Request" , observable.get("CertReq"));

            if (((Boolean)(observable.get("newCertReq"))).booleanValue()
                    && !(oldUrl.equals(param.get("url")))) {
                try {
                    //attempt to contect cms
                    oldUrl = (String)(param.get("url"));
                    Comm cmsUrl = new Comm(oldUrl, /*null*/urlParam, true);
                    cmsUrl.run();
                    /*System.out.println(cmsUrl.getData());*/
                    //explain.setVisible(false);
                    explain.setText(explainURL);
                    if (cmsUrl.getError() != null) {
                        //cms didn't respond
                        certReq.setText(
                                resource.getString("CertRequestCertPane",
                                "cmsNotResponding"));
                        Debug.println("CertRequestCertPane:"+
                                cmsUrl.getError());
                    } else if ((cmsUrl.getData() != null) &&
                            (cmsUrl.getData().trim().length() != 0)) {
                        //cms return a message

                        JEditorPane editor = new JEditorPane();
                        editor.setBorder(new EmptyBorder(0, 0, 0, 0));
                        editor.setEditable(false);
                        //editor.setOpaque(false);

                        //display cms's message
                        Debug.println(cmsUrl.getData());
                        StringReader reader =
                                new StringReader(cmsUrl.getData());
                        editor.setEditorKit(
                                editor.createEditorKitForContentType("text/html"));
                        Document dstDoc = editor.getDocument();
                        editor.getEditorKit().read(reader, dstDoc, 0);

                        certReq.setText(editor.getText());
                    }

                    observable.put("newCertReq", new Boolean(false));
                } catch (Exception e) {
                    certReq.setText(
                            resource.getString("CertRequestCertPane", "unableToParse"));
                    Debug.println("CertRequestCertPane:"+e);

                }
            }

        } else if (show) {
            //if request via e-mail
            explain.setText(explainEMail);
            certReq.setText((String)(observable.get("CertReq")));
            explain.setVisible(true);
        }

        scrollPane.validate();

        return show;
    }

    MultilineLabel explain;
    ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();
    public CertRequestCertPane() {
        super();
        setLayout(new GridBagLayout());


        copy = JButtonFactory.create(
                resource.getString("CertRequestCertPane", "copyLabel"));

        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertRequestCertPane", "title")));

        int y = 0;

        explainEMail = resource.getString("CertRequestCertPane", "explain");
        explainURL = resource.getString("CertRequestCertPane", "explain2");


        explain = new MultilineLabel(explainEMail);
        GridBagUtil.constrain(this, explain, 0, ++y, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, scrollPane, 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);


        copy.setActionCommand("COPY");
        copy.addActionListener(new CertPaneActionListener());
        GridBagUtil.constrain(this, copy, 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.NONE, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, ++y,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(this,
                new JLabel(
                resource.getString(null, "clickNextToContinue")), 0,
                ++y, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
    }

    /*public static void main(String arg[]) {
         JFrame f = new JFrame();
         f.getContentPane().add("North", new CertRequestCertPane());
         f.setSize(400,400);
         f.show();
     }*/

}
