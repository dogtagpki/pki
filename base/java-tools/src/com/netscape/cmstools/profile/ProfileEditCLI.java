//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2014 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.profile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.cmstools.cli.CLI;

public class ProfileEditCLI extends CLI {

    public ProfileCLI profileCLI;

    public ProfileEditCLI(ProfileCLI profileCLI) {
        super("edit", "Edit profiles (config-store format)", profileCLI);
        this.profileCLI = profileCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No Profile ID specified.");
        }

        String profileId = cmdArgs[0];

        ProfileClient profileClient = profileCLI.getProfileClient();

        // read profile into temporary file
        Properties orig = profileClient.retrieveProfileRaw(profileId);
        String enabled = orig.getProperty("enable");
        if (Boolean.valueOf(enabled)) {
            throw new Exception("Cannot edit profile. Profile must be disabled.");
        }
        Path tempFile = Files.createTempFile("pki", ".cfg");

        try {
            orig.store(Files.newOutputStream(tempFile), null);

            // invoke editor on temporary file
            String editor = System.getenv("EDITOR");
            String[] command;
            if (editor == null || editor.trim().isEmpty()) {
                command = new String[] {"/usr/bin/env", "vi", tempFile.toString()};
            } else {
                command = new String[] {editor.trim(), tempFile.toString()};
            }
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.inheritIO();
            int exitCode = pb.start().waitFor();
            if (exitCode != 0) {
                throw new Exception("Exited abnormally.");
            }

            // read data from temporary file and modify if changed
            Properties cur = new Properties();
            cur.load(Files.newInputStream(tempFile));

            if (!cur.equals(orig)) {
                profileClient.modifyProfileRaw(profileId, cur);
            }
            cur.store(System.out, null);
        } finally {
            Files.delete(tempFile);
        }
    }
}
