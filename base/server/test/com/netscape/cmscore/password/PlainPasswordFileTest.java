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

    // Successful cases
    // Expected key-value pair
    String[] refString1 = { "Truth", "Beauty" };
    String[] testString1 = {
            "Truth=Beauty", "Truth= Beauty", "Truth=Beauty ", "Truth= Beauty ",
            "Truth =Beauty", "Truth = Beauty", "Truth =Beauty ", "Truth = Beauty ",
            " Truth=Beauty", " Truth= Beauty", " Truth=Beauty ", " Truth= Beauty ",
            " Truth =Beauty", " Truth = Beauty", " Truth =Beauty ", " Truth = Beauty "
    };

    String[] refString2 = { "Welcome Message", "Hello World" };
    String[] testString2 = {
            "Welcome Message=Hello World", "Welcome Message= Hello World",
            "Welcome Message=Hello World ", "Welcome Message= Hello World ",

            "Welcome Message =Hello World", "Welcome Message = Hello World",
            "Welcome Message =Hello World ", "Welcome Message = Hello World ",

            " Welcome Message=Hello World", " Welcome Message= Hello World",
            " Welcome Message=Hello World ", " Welcome Message= Hello World ",

            " Welcome Message =Hello World", " Welcome Message = Hello World",
            " Welcome Message =Hello World ", " Welcome Message = Hello World "
    };

    String[] testString3 = { " \n", "# Ignored line 1", "   # Ignored line 2" };

    // Negative cases
    String[] testString4 = {
            "hello",
            "hello:world",
            "hello world"
    };

    @Before
    public void preTestSetup() throws IOException
    {
        pwdFile = new PlainPasswordFile();
        createdFile = folder.newFile("tempPasswordFile");
    }

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Rule
    public ExpectedException expectedException= ExpectedException.none();

    @Test
    public void testInitNormal() throws IOException {
        writeToFileAndInit(createdFile, testString1);
        // Since all all keys and values are equivalent, only 1 value should be loaded
        Assert.assertEquals(1, pwdFile.getSize());
        // Check whether the value is correctly stored and retrieved
        Assert.assertEquals(refString1[1], pwdFile.getPassword(refString1[0], 0));

    }

    @Test
    public void testInitWithSpace() throws IOException {
        writeToFileAndInit(createdFile, testString2);
        Assert.assertEquals(1, pwdFile.getSize());
        Assert.assertEquals(refString2[1], pwdFile.getPassword(refString2[0], 0));

    }

    @Test
    public void testComments() throws IOException {
        writeToFileAndInit(createdFile, testString3);
        // There should be no values present since the file contains only comments
        // and newline
        Assert.assertEquals(0, pwdFile.getSize());
    }

    @Test
    public void testException() throws IOException {
        expectedException.expect(IOException.class);
        writeToFileAndInit(createdFile, testString4);
    }

    private void writeToFileAndInit(File file, String[] strArray) throws IOException {
        for (String str : strArray) {
            FileUtils.writeStringToFile(file, str + "\n", (Charset) null, true);
        }
        pwdFile.init(createdFile.getAbsolutePath());
    }

}
