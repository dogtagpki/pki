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

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import com.netscape.cmsutil.password.PlainPasswordFile;

/**
 * @author Dinesh Prasanth M K <dmoluguw@redhat.com>
 *
 */
public class PlainPasswordFileTest {

    PlainPasswordFile pwdFile;
    File createdFile;
    private final int TESTCASE_ENTRY = 0;
    private final int TESTCASE_KEY = 1;
    private final int TESTCASE_VALUE = 2;

    // Successful cases
    String[][] testCases = {
            { "Truth=Beauty", "Truth", "Beauty" }, // No spaces
            { " Truth = Beauty ", "Truth", "Beauty" }, // Check for spaces
            { "Welcome Message=Hello World", "Welcome Message", "Hello World" }, // No spaces
            { " Welcome Message = Hello World ", "Welcome Message", "Hello World" },
            { "\n" }, // Empty line
            { "# Ignored line 1" }, // Commented line
            { "hello" },
            { "hello:world" },
            { "hello world" }
    };

    @Before
    public void preTestSetup() throws IOException {
        pwdFile = new PlainPasswordFile();
        createdFile = folder.newFile("tempPasswordFile");
    }

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

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
    public void testComments() throws IOException {
        testHelper(5, true);
    }

    @Test
    public void testNoValue() throws IOException {
        expectedException.expect(IOException.class);
        testHelper(6, false);
    }

    @Test
    public void testWrongDelimiter() throws IOException {
        expectedException.expect(IOException.class);
        testHelper(7,  false);
    }

    @Test
    public void testSpaceDelimiter() throws IOException {
        expectedException.expect(IOException.class);
        testHelper(8, false);
    }

    private void writeToFileAndInit(File file, String string) throws IOException {
        FileUtils.writeStringToFile(file, string + "\n", (Charset) null, true);
        pwdFile.init(createdFile.getAbsolutePath());
    }

    private void testHelper(int testCaseId, boolean isEmpty) throws IOException {
        writeToFileAndInit(createdFile, testCases[testCaseId][TESTCASE_ENTRY]);
        if (isEmpty) {
            Assert.assertEquals(0, pwdFile.getSize());
        } else {
            Assert.assertEquals(testCases[testCaseId][TESTCASE_VALUE],
                    pwdFile.getPassword(testCases[testCaseId][TESTCASE_KEY], 0));
        }
    }

}
