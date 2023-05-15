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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.netscape.cmsutil.password.PlainPasswordFile;

/**
 * @author Dinesh Prasanth M K <dmoluguw@redhat.com>
 *
 */
public class PlainPasswordFileTest {

    static PlainPasswordFile pwdFile;
    @TempDir
    static Path folder;
    static File createdFile;
    private final int TESTCASE_ENTRY = 0;
    private final int TESTCASE_KEY = 1;
    private final int TESTCASE_VALUE = 2;

    // Successful cases
    String[][] testCases = {
            { "Truth=Beauty", "Truth", "Beauty" }, // No spaces
            { " Truth = Beauty ", "Truth", "Beauty" }, // Check for spaces
            { "Welcome Message=Hello World", "Welcome Message", "Hello World" }, // No spaces
            { " Welcome Message = Hello World ", "Welcome Message", "Hello World" },
            { "" }, // Empty line
            { " " }, // Non-empty line
            { "# Ignored line 1" }, // Commented line
            { " # Ignored line 2" }, // Commented line with leading space
            { "hello" },
            { "hello:world" },
            { "hello world" }
    };

    @BeforeEach
    public void preTestSetup() {
        pwdFile = new PlainPasswordFile();
        createdFile = new File(folder + "tempPasswordFile");
    }

    @Test
    public void testInitNormal() throws IOException {
        testHelper(0, false);
    }

    @Test
    public void testInitNormalWithSpace() throws IOException {
        testHelper(1, false);
    }

    @Test
    public void testInitWithSpaceInside() throws IOException {
        testHelper(2, false);
    }

    @Test
    public void testInitWithSpaceInsideAndOutside() throws IOException {
        testHelper(3, false);
    }

    @Test
    public void testEmptyLine() throws IOException {
        testHelper(4, true);
    }

    @Test
    public void testNonEmptyLine() throws IOException {
        testHelper(5, true);
    }

    @Test
    public void testComments() throws IOException {
        testHelper(6, true);
    }

    @Test
    public void testCommentsWithLeadingSpace() throws IOException {
        testHelper(7, true);
    }

    @Test
    public void testNoValue() {
        assertThrows(IOException.class, () -> testHelper(8, false));
    }

    @Test
    public void testWrongDelimiter() {
        assertThrows(IOException.class, () -> testHelper(9, false));
    }

    @Test
    public void testSpaceDelimiter() {
        assertThrows(IOException.class, () -> testHelper(10, false));
    }

    private void writeToFileAndInit(File file, String string) throws IOException {
        FileUtils.writeStringToFile(file, string + "\n", (Charset) null, true);
        pwdFile.init(createdFile.getAbsolutePath());
    }

    private void testHelper(int testCaseId, boolean isEmpty) throws IOException {
        writeToFileAndInit(createdFile, testCases[testCaseId][TESTCASE_ENTRY]);
        if (isEmpty) {
            assertEquals(0, pwdFile.getSize());
        } else {
            assertEquals(testCases[testCaseId][TESTCASE_VALUE],
                    pwdFile.getPassword(testCases[testCaseId][TESTCASE_KEY], 0));
        }
    }

}
