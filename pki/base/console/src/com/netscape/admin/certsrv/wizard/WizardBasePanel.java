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
package com.netscape.admin.certsrv.wizard;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import javax.swing.border.*;
import java.net.*;
import java.io.*;

/**
 * Wizard Base Panel
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class WizardBasePanel extends CMSBasePanel implements MouseMotionListener,
  ConfigServlet {

    /*==========================================================
     * variables
     *==========================================================*/
    protected String mTitle;
    protected String mErrorString;
    protected String mNextString =
      mResource.getString("GENERALWIZARD_LABEL_NEXT_LABEL"); 
    protected String mPanelName;
    public static long mSeed;

	/*==========================================================
     * constructors
     *==========================================================*/
    public WizardBasePanel(String name) {
      super(name);
      mTitle = mResource.getString(name+"_TITLE");
      mPanelName = name;
        addMouseMotionListener(this);
    }

    public WizardBasePanel(String name, ResourceBundle rb) {
        super(name, rb);
        mPanelName = name;
        try {
            mTitle = mResource.getString(name+"_TITLE");
        } catch (MissingResourceException e) {
            mTitle = "Missing Title";
        }
        addMouseMotionListener(this);
    }

    protected void init() {

/*
        GridBagConstraints gbc = new GridBagConstraints();
      
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.SOUTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        JLabel nextLabel = new JLabel(mNextString);
        add(nextLabel, gbc);

        setBorder(makeTitledBorder(mPanelName));
*/
    }

    protected JTextArea createTextArea(String str, int row, int col) {
        JTextArea desc = new JTextArea(str, row, col);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());

        return desc;
    }

    protected JTextArea createTextArea(String str) {
        JTextArea desc = new JTextArea(str);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
        desc.setLineWrap(true);
        desc.setWrapStyleWord(true);

        return desc;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    /**
     * Returns the title of the tab
     * @return string representation of the title
     */
    public String getTitle() {
		return mTitle;
	}

	/**
	 * Returns the error string
	 */
    public String getErrorMessage() {
        return  mErrorString;
    }

    /**
     * Set error string
     */
    public void setErrorMessage(String keyword) {
        try {
            String err = mResource.getString(mPanelName+"_DIALOG_"+keyword+"_MESSAGE");
            mErrorString = err;
        } catch (MissingResourceException e) {
            mErrorString = keyword;
        }
    }

    public void cleanUpWizardInfo(WizardInfo wizardInfo) {
        wizardInfo.remove("NMC_WARNINFO");
        wizardInfo.remove("NMC_ERRINFO");
        wizardInfo.remove("NMC_STATUS");
    }
    
    public String getErrorMessage(WizardInfo wizardInfo) {
        String value = (String)wizardInfo.get("NMC_ERRINFO");
        if (value != null || value.trim().length() == 0)
            return value;
        value = (String)wizardInfo.get("NMC_WARNINFO");
        if (value != null || value.trim().length() == 0)
            return value;
      
        return null;
    }

    public boolean send(String host, int port, String servlet, String rawData, 
      WizardInfo wizardInfo) {
        try {
            Socket socket = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            InputStream is = socket.getInputStream();
            String spost = "POST "+servlet+" HTTP/1.0\r\n";
            byte[] b = rawData.getBytes();
            dos.writeBytes(spost);
            dos.writeBytes("User-Agent: HTTPTool/1.0\r\n");
            dos.writeBytes("Content-length: " + b.length + "\r\n");
            dos.writeBytes("Content-Type: application/x-www-form-urlencoded\r\n");
            dos.writeBytes("\r\n");
            dos.write(b);
            dos.writeBytes("\r\n");
            dos.flush();

            ByteArrayOutputStream bstream = new ByteArrayOutputStream(10000);
            while (true)
            {
                int r = is.read();
                if (r == -1)
                    break;
                bstream.write(r);
            }

            socket.close();
            String test = bstream.toString();

            StringTokenizer tokenizer = new StringTokenizer(test, "\r\n");
            while (tokenizer.hasMoreTokens()) {
                String nvalue = tokenizer.nextToken();
                System.out.println("tokenizer="+nvalue);
                StringTokenizer tokenizer1 = new StringTokenizer(nvalue, ":");
                int numTokens = tokenizer1.countTokens();
                if (numTokens == 2) {
                    String name = tokenizer1.nextToken().trim();
                    String value = tokenizer1.nextToken().trim();
                    wizardInfo.put(name, value);
                }
            }
            bstream.close();
            String sendStatus = (String)wizardInfo.get("NMC_STATUS");
            if (sendStatus.equals("0")) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) { 
        }

        return false;
    }

    public boolean send(String rawData, WizardInfo wizardInfo) {
        try {
            Socket socket = new Socket("droopy-linux.sfbay.redhat.com", 1924);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            InputStream is = socket.getInputStream();
            String servlet = "/config/configSubsystem";
            String spost = "POST "+servlet+" HTTP/1.0\r\n";
            byte[] b = rawData.getBytes();
            dos.writeBytes(spost);
            dos.writeBytes("User-Agent: HTTPTool/1.0\r\n");
            dos.writeBytes("Content-length: " + b.length + "\r\n");
            dos.writeBytes("Content-Type: application/x-www-form-urlencoded\r\n");
            dos.writeBytes("\r\n");
            dos.write(b);
            dos.writeBytes("\r\n");
            dos.flush();

            ByteArrayOutputStream bstream = new ByteArrayOutputStream(10000);
            while (true)
            {
                int r = is.read();
                if (r == -1)
                    break;
                bstream.write(r);
            }

            socket.close();
            String test = bstream.toString();

            StringTokenizer tokenizer = new StringTokenizer(test, "\r\n");
            while (tokenizer.hasMoreTokens()) {
                String nvalue = tokenizer.nextToken();
                System.out.println("tokenizer="+nvalue);
                StringTokenizer tokenizer1 = new StringTokenizer(nvalue, ":");
                int numTokens = tokenizer1.countTokens();
                if (numTokens == 2) {
                    String name = tokenizer1.nextToken().trim();
                    String value = tokenizer1.nextToken().trim();
                    wizardInfo.put(name, value);                        
                }
            }
            bstream.close();
            String sendStatus = (String)wizardInfo.get("NMC_STATUS");
            if (sendStatus.equals("0")) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
        }

        return false;
    }

    /*==========================================================
	 * EVENT HANDLER METHODS
     *==========================================================*/

	/*
	 * mouselistener events - for JPanel
	 */

	/**
	 * This lets us know when someone move the mouse, so we can
	 * keep coordidate of mouse posion and use this value as a random seed
	 */
	public void mouseDragged(MouseEvent e) {
		// Do nothing for this
	}

	public void mouseMoved(MouseEvent e) {
		// Keep tracking coordinate values
		long x = e.getX();
		long y = e.getY();
		
		long top = mSeed >> 62;
		mSeed = ((mSeed << 2) ^ top ^ (x<<8) ^ (y)) % Long.MAX_VALUE;
	}
}
