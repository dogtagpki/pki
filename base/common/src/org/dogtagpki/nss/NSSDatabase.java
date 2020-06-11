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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.nss;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.io.FileUtils;

import com.netscape.cmsutil.password.IPasswordStore;

/**
 * @author Endi S. Dewata
 */
public class NSSDatabase {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(NSSDatabase.class);

    Path path;
    IPasswordStore passwordStore;

    public NSSDatabase(Path path) {
        this.path = path;
    }

    public NSSDatabase(File directory) {
        this(directory.toPath());
    }

    public NSSDatabase(String directory) {
        this(Paths.get(directory));
    }

    public Path getPath() {
        return path;
    }

    public void setPath(Path path) {
        this.path = path;
    }

    public File getDirectory() {
        return path.toFile();
    }

    public void setDirectory(File directory) {
        path = directory.toPath();
    }

    public IPasswordStore getPasswordStore() {
        return passwordStore;
    }

    public void setPasswordStore(IPasswordStore passwordStore) {
        this.passwordStore = passwordStore;
    }

    public boolean exists() {
        return Files.exists(path);
    }

    public void create() throws Exception {
        create(null);
    }

    public void create(String password) throws Exception {
        create(password, false);
    }

    public void create(String password, boolean enableTrustPolicy) throws Exception {

        logger.info("Creating NSS database in " + path);

        Files.createDirectories(path);

        Path passwordPath = path.resolve("password.txt");

        try {
            List<String> command = new ArrayList<>();
            command.add("certutil");
            command.add("-N");
            command.add("-d");
            command.add(path.toAbsolutePath().toString());

            if (password == null) {
                command.add("--empty-password");

            } else {
                try (PrintWriter out = new PrintWriter(new FileWriter(passwordPath.toFile()))) {
                    out.println(password);
                }

                command.add("-f");
                command.add(passwordPath.toAbsolutePath().toString());
            }

            debug(command);

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.inheritIO();

            Process p = pb.start();
            int rc = p.waitFor();

            if (rc != 0) {
                throw new Exception("Command failed: rc=" + rc);
            }

        } finally {
            if (Files.exists(passwordPath)) Files.delete(passwordPath);
        }

        if (enableTrustPolicy && !moduleExists("p11-kit-trust")) {
            addModule("p11-kit-trust", "/usr/share/pki/lib/p11-kit-trust.so");
        }
    }

    public boolean moduleExists(String name) throws Exception {

        logger.info("Checking module " + name);

        List<String> command = new ArrayList<>();
        command.add("modutil");
        command.add("-dbdir");
        command.add(path.toAbsolutePath().toString());
        command.add("-rawlist");

        debug(command);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);

        Process p = pb.start();

        // searching for name="<module>"
        String pattern = " name=\"" + name + "\" ";

        try (Reader reader = new InputStreamReader(p.getInputStream());
                BufferedReader in = new BufferedReader(reader)) {

            String line;
            while ((line = in.readLine()) != null) {
                if (line.contains(pattern)) return true;
            }
        }

        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }

        return false;
    }

    public void addModule(String name, String library) throws Exception {

        logger.info("Installing " + name + " module with " + library);

        List<String> command = new ArrayList<>();
        command.add("modutil");
        command.add("-dbdir");
        command.add(path.toAbsolutePath().toString());
        command.add("-add");
        command.add(name);
        command.add("-libfile");
        command.add(library);
        command.add("-force");

        debug(command);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);

        Process p = pb.start();

        try (Writer writer = new OutputStreamWriter(p.getOutputStream());
                PrintWriter out = new PrintWriter(writer)) {

            // modutil will generate the following question:

            // WARNING: Manually adding a module while p11-kit is enabled could cause
            // duplicate module registration in your security database. It is suggested
            // to configure the module through p11-kit configuration file instead.
            //
            // Type 'q <enter>' to abort, or <enter> to continue:

            // respond with <enter>
            out.println();
        }

        int rc = p.waitFor();

        if (rc != 0) {
            throw new Exception("Command failed: rc=" + rc);
        }
    }

    public void delete() throws Exception {
        FileUtils.deleteDirectory(path.toFile());
    }

    public void debug(Collection<String> command) {

        if (logger.isDebugEnabled()) {

            StringBuilder sb = new StringBuilder("Command:");

            for (String c : command) {

                boolean quote = c.contains(" ");

                sb.append(' ');

                if (quote) sb.append('"');
                sb.append(c);
                if (quote) sb.append('"');
            }

            logger.debug(sb.toString());
        }
    }
}
