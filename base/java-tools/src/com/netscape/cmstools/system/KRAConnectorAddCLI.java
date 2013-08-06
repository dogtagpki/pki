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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmstools.system;

import java.io.FileInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.system.KRAConnectorInfo;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Ade Lee
 */
public class KRAConnectorAddCLI extends CLI {

    public KRAConnectorCLI kraConnectorCLI;

    public KRAConnectorAddCLI(KRAConnectorCLI kraConnectorCLI) {
        super("add", "Add KRA Connector", kraConnectorCLI);
        this.kraConnectorCLI = kraConnectorCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <File Name>", options);
    }

    public void execute(String[] args) throws Exception {

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cLineArgs = cmd.getArgs();

        if (cLineArgs.length < 1) {
            System.err.println("Error: No file name specified.");
            printHelp();
            System.exit(-1);
        }

        FileInputStream fis = new FileInputStream(cLineArgs[0].trim());

        JAXBContext context = JAXBContext.newInstance(KRAConnectorInfo.class);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        KRAConnectorInfo info = (KRAConnectorInfo) unmarshaller.unmarshal(fis);

        kraConnectorCLI.kraConnectorClient.addConnector(info);

        MainCLI.printMessage("Added KRA Connector");
    }
}
