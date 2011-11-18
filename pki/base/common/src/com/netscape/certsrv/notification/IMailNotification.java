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
package com.netscape.certsrv.notification;


import java.io.IOException;
import java.util.Vector;


/**
 * This class handles mail notification via SMTP.
 * This class uses <b>smtp.host</b> in the configuration for smtp
 * host.  The port default (25) is used.  If no smtp specified, local
 * host is used
 *
 * @version $Revision$, $Date$
 */
public interface IMailNotification {

    /**
     * send one message to one or more addressees
     */
    public void sendNotification() throws IOException, ENotificationException;

    /**
     * sets the "From" field
     * @param from email address of the sender
     */
    public void setFrom(String from);

    /**
     * sets the "Subject" field
     * @param subject subject of the email
     */
    public void setSubject(String subject);

    /**
     * sets the "Content-Type" field
     * @param contentType content type of the email
     */
    public void setContentType(String contentType);

    /**
     * sets the content of the email
     * @param content the message content
     */
    public void setContent(String content);

    /**
     * sets the recipients' email addresses
     * @param addresses a list of email addresses of the recipients
     */
    public void setTo(Vector<String> addresses);

    /**
     * sets the recipient's email address
     * @param to address of the recipient email address
     */
    public void setTo(String to);

}
