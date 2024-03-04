/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/

package com.netscape.management.client.util;

import java.io.*;
import java.util.zip.*;

/**
 * A utility class for modifying swing package name on the fly
 */
class SwingPackageNameConverter {

    // Java class file tags
    public static final int CONST_CLASS = 7;
    public static final int CONST_FIELDREF = 9;
    public static final int CONST_METHODREF = 10;
    public static final int CONST_IMETHODREF = 11; // Interface MethodRref
    public static final int CONST_STRING = 8;
    public static final int CONST_INTEGER = 3;
    public static final int CONST_FLOAT = 4;
    public static final int CONST_LONG = 5;
    public static final int CONST_DOUBLE = 6;
    public static final int CONST_NAMEANDTYPE = 12;
    public static final int CONST_UTF8 = 1;


    // Constansts for accessing strings in the conversion Table
    private static final int OLD_PACKAGE = 0;
    private static final int NEW_PACKAGE = 1;
    private static final int PLAF_WINDOWS = 2;
    private static final int PLAF_MOTIF = 3;

    // Package name conversion table. Every occurrence of OLD_PACKAGE
    // name should be replaced with NEW_PACKAGE name except for 
    // OLD_PACKAGE + PLAF_WINDOWS and OLD_PACKAGE + PLAF_MOTIF

    private static String[][] convTable = { 
    // OLD_PACKAGE           NEW_PACKAGE    PLAF_WINDOWS      PLAF_MOTIF         
      {"com/sun/java/swing", "javax/swing", "/plaf/windows/", "/plaf/motif/"},
      {"com$sun$java$swing", "javax$swing", "$plaf$windows$", "$plaf$motif$"},
      {"com.sun.java.swing", "javax.swing", ".plaf.windows.", ".plaf.motif."}
    };
                                         
    // Auxiliary buffer, see convert() method
    private static byte[] buf = new byte[1024*16];

    private static final String debugTag = "ClassLoader: ";
    
    /**
     * Replace all occurrences of "com/sun/java/swing" with "javax/swing"
     * for packages other than plaf/motif and plaf/windows
     * @param in Constant Pool string
     * @return Possibly converted input string
     */
    static String convertPackageName(String in) {

        for (int i=0; i < convTable.length; i++) {

            int pos = -1;
            int fromIndex =0;
            String[] convList = convTable[i];
            StringBuffer sb = null;

            while ((pos=in.indexOf(convList[OLD_PACKAGE], fromIndex)) >=0) {

                int subpackageIndex = pos + convList[OLD_PACKAGE].length();

                if (sb == null) {
                    sb = new StringBuffer();
                }

                sb.append(in.substring(fromIndex,pos));

                if (in.indexOf(convList[PLAF_WINDOWS], subpackageIndex)  == subpackageIndex) {
                    sb.append(convList[OLD_PACKAGE]); // keep package name
                }
                else if (in.indexOf(convList[PLAF_MOTIF], subpackageIndex)  == subpackageIndex) {
                    sb.append(convList[OLD_PACKAGE]); // keep package name
                }
                else {
                    sb.append(convList[NEW_PACKAGE]); // change package name
                }

                fromIndex = subpackageIndex;
            }

            // The input string is modified if a StringBuffer was created
            if (sb != null) {
                sb.append(in.substring(fromIndex, in.length()));

                if (Debug.getTraceLevel() == 9) {
                    Debug.println(9, debugTag + in + " -> " + sb.toString());
                }                                
                in = sb.toString();
            }
        }

        return in;
    }


    /**
     * Read a class bytecodes from an input stream and write to an output
     * straem converting the Java classfile Constant Pool so that all
     * occurrences of swing1.0 package name are replaced with swing1.1
     * package name.
     * @param in Input Stream
     * @param out Output Stream
     */
    public static synchronized void convert(InputStream in, OutputStream out) throws IOException, Exception {

        int magic = 0;
        short majorVersion = -1, minorVersion =-1;
        DataInputStream dis = new DataInputStream(in);
        DataOutputStream dos = new DataOutputStream(out);
        int constantPoolCount, len;
        byte constTag;

        magic = dis.readInt();
        if (magic != (int) 0xCAFEBABE) {
            throw new Exception("Not a java class file");
        }        
        dos.writeInt(magic);
        
        dos.writeShort(majorVersion = dis.readShort());
        dos.writeShort(minorVersion = dis.readShort());
    
        if (majorVersion != 3 && minorVersion != 45) {
            Debug.println(0, debugTag + "majorVersion="+majorVersion + " minorVersion="+minorVersion);
        }            
        
        // Extract Constant Pool and do swing package name conversion
        byte[] constPool = convertConstPool(dis);
        dos.write(constPool);
        
        /**
         * Now copy the rest of the class file as is
         */                 
        try {
            while ((len=dis.read(buf)) > 0) {
                dos.write(buf,0, len);
            }
        }    
        catch (EOFException e) {
            // Under jdk 1.1 Zip file throws exception when trying to read after EOF
            ;
        }
        catch (Exception e) {
            Debug.println(0, "SwingPackageNameConverter.convert " + e);
            throw e;
        }
        
        // Done, flush the output
        dos.flush();
    }

    /**
     * Extract constPool and make swing package name conversion on the fly
     */
    static byte[] convertConstPool(DataInputStream dis) throws Exception {
            
        ByteArrayOutputStream pool = new ByteArrayOutputStream(1024);
        DataOutputStream dos = new DataOutputStream(pool);
        byte constTag=0;
        int cnt = 0;

        dos.writeShort(cnt = dis.readShort());
        
        // Constant pool entry at index zero is for the JVM internal
        // use only and it is not present in the constant_pool table 
        // of the class file. A valied constant_pool index is 
        // (1 <= index < constantPoolCount). Therefor we initialize
        // loop counter with 1 rather than zero.
        for (int i = 1; i < cnt; i++) {
            
            dos.writeByte(constTag = dis.readByte());

            switch (constTag) {
                case CONST_UTF8:
                    // Convert package name if the string starts with the old name
                      dos.writeUTF(convertPackageName(dis.readUTF()));
                       break;

                case CONST_CLASS:
                    dos.writeShort(dis.readShort());
                    break;

                case CONST_STRING:
                    dos.writeShort(dis.readShort());
                    break;
                    
                case CONST_FIELDREF:
                    dos.writeShort(dis.readShort());
                    dos.writeShort(dis.readShort());
                    break;

                case CONST_METHODREF:
                case CONST_IMETHODREF:
                    dos.writeShort(dis.readShort());
                    dos.writeShort(dis.readShort());
                    break;
                    
                case CONST_NAMEANDTYPE:
                    dos.writeShort(dis.readShort());
                    dos.writeShort(dis.readShort());
                    break;

                case CONST_INTEGER:
                    dos.writeInt(dis.readInt());
                    break;
                case CONST_FLOAT:
                    dos.writeFloat(dis.readFloat());
                    break;
    
                // LONG and DOUBLE constants are assumed to occupy two
                // slots, so the loop counter is increased for two units
                case CONST_LONG:
                    dos.writeLong(dis.readLong());
                    i++; // counted as two slots in the table
                    break;
                case CONST_DOUBLE:
                    dos.writeDouble(dis.readDouble());
                    i++; // counted as two slots in the table
                    break;

                default:
                    throw new Exception("Bad constant tag " + constTag + " at position " + i);
            }
        }
        
        dos.flush();
        return pool.toByteArray();
    }
    
    
    public static void convertJar(String jar) {
        /*if (Debug.timeTraceEnabled()) {
            Debug.println(Debug.TYPE_RSPTIME, "Convert " + jar + "...");
        }*/
        long t0 = System.currentTimeMillis();

        try {

            ZipFile inputJar = new ZipFile(jar);
            int fileCnt = 0, fileDone = 0;
            
            // Get the number of files in the jar.
            // In jdk 1.1 ZipFile.size() method does bot exist
            try {
                fileCnt = inputJar.size();
            }
            catch (Throwable e) {
                System.err.println("ZipFile.size() method missing");
                fileCnt = -1;
            }
            finally {
                inputJar.close();
            }
                
            ZipInputStream inZip = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(jar)));
            ZipOutputStream  outZip = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(jar+".comp")));

            ZipEntry inEntry = null;
            ZipEntry outEntry = null;
            int size=0, cnt=0, len=0;
            byte[] storage = new byte[512];
            while((inEntry = inZip.getNextEntry()) != null) {
                  
                if (inEntry.getName().endsWith(".class")) {
                    outEntry = new ZipEntry(inEntry.getName());
                    outZip.putNextEntry(outEntry);

                    convert(inZip, outZip);
                }

                else {
                    outEntry = new ZipEntry(inEntry.getName());
                    outZip.putNextEntry(outEntry);

                    size = (int)(inEntry.getSize());
                    cnt = 0;
                    for (cnt=0; cnt < size; cnt+=len) {
                        len = inZip.read(storage, 0, 512);
                        outZip.write(storage, 0, len);
                    }
                }

                outZip.closeEntry();
                inZip.closeEntry();
              
                if (fileCnt == -1) {
                    System.err.print("Converting...\r");
                }
                else {
                    fileDone++;
                    System.err.print("Converted " + fileDone +
                         " out of " + fileCnt + " files...\r");
                }
             }
             inZip.close();
             outZip.close();

             /*if (Debug.timeTraceEnabled()) {
                 Debug.println(Debug.TYPE_RSPTIME, "Done");
             }*/
             long t1 = System.currentTimeMillis();
             System.err.println("");
             System.err.println("Conversion time " + (t1-t0)/1000. + " sec");
        }
        catch (Exception e) {
            System.err.println(e);
            e.printStackTrace(System.err);
        }
    }

    public static void main00(String[] args) {
        if (args.length != 1 && args.length != 2) {
            System.err.println("Usage: SwingPackageNameConverter <name>.class [outputDir]");
            System.exit(1);
        }
        try {
            Debug.setTraceLevel(9);
            FileInputStream  fin = new FileInputStream(args[0]);
            if (args.length == 2) {
                FileOutputStream fout = new FileOutputStream(new File(args[1]));
                convert(fin, fout);
            }
            else {
                convert(fin, new ByteArrayOutputStream());
            }
        }
        catch (Exception ex) {
            System.err.println(ex);
            ex.printStackTrace();
        }    
    }
        
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: SwingPackageNameConverter zip-or-jar-file");
            System.exit(1);
        }
        try {
            //Debug.setTraceMode("rsptime");
            convertJar(args[0]);
        }
        catch (Exception ex) {
            System.err.println(ex);
            ex.printStackTrace();
        }    
    }
}
