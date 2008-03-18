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
package com.netscape.cmscore.dbs;


import java.util.*;
import java.io.*;
import java.math.*;
import netscape.ldap.*;
import netscape.security.x509.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.dbs.repository.*;
import com.netscape.certsrv.dbs.certdb.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.dbs.keydb.*;
/**
 * A class represents a generic repository. It maintains unique 
 * serial number within repository.
 * <P>
 * To build domain specific repository, subclass should be
 * created.
 * <P>
 *
 * @author galperin
 * @author thomask
 * @version $Revision: 1.4
 *       
 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */

public abstract class Repository implements IRepository {

    private static final BigInteger BI_ONE = new BigInteger("1");
    private BigInteger BI_INCREMENT = null;
    // (the next serialNo to be issued) - 1
    private BigInteger mSerialNo = null; 
    // the serialNo attribute stored in db
    private BigInteger mNext = null;

    private String mMaxSerial = null;
    private String mMinSerial = null;

    private BigInteger mMinSerialNo = null;
    private BigInteger mMaxSerialNo = null;

    private IDBSubsystem mDB = null;
    private String mBaseDN = null;
    private boolean mInit = false;


    private BigInteger mLastSerialNo = null;
    /**
     * Constructs a repository.
     * <P>
     */
    public Repository(IDBSubsystem db, int increment, String baseDN) 
        throws EDBException {
        mDB = db;
        mBaseDN = baseDN;


        BI_INCREMENT = new BigInteger(Integer.toString(increment));

        // register schema
        IDBRegistry reg = db.getRegistry();

        /**
         if (!reg.isObjectClassRegistered(
         RepositoryRecord.class.getName())) {
         String repRecordOC[] = new String[2];
         repRecordOC[0] = RepositorySchema.LDAP_OC_TOP;
         repRecordOC[1] = RepositorySchema.LDAP_OC_REPOSITORY;
         reg.registerObjectClass(
         RepositoryRecord.class.getName(), repRecordOC);
         }
         if (!reg.isAttributeRegistered(RepositoryRecord.ATTR_SERIALNO)) {
         reg.registerAttribute(RepositoryRecord.ATTR_SERIALNO,
         new BigIntegerMapper(RepositorySchema.LDAP_ATTR_SERIALNO));
         }
         **/
    }

    /**
     * Resets serial number.
     */
    public void resetSerialNumber(BigInteger serial) throws EBaseException
    {
        IDBSSession s = mDB.createSession();
                                                                                
        try {
            String name = mBaseDN;
            ModificationSet mods = new ModificationSet();
            mods.add(IRepositoryRecord.ATTR_SERIALNO,
                Modification.MOD_REPLACE, serial);
            s.modify(name, mods);
        } finally {
            if (s != null)
                s.close();
        }
    }

    /**
     * Retrieves the next serial number attr in db.
     * <P>
     *
     * @return next serial number
     */
    private BigInteger getSerialNumber() throws EBaseException {
        IDBSSession s = mDB.createSession();

        CMS.debug("Repository: getSerialNumber.");
        RepositoryRecord rec = null;

        try {
            if (s != null) rec = (RepositoryRecord) s.read(mBaseDN);
        } finally { 
            if (s != null) s.close();
        }

        if( rec == null ) {
            CMS.debug( "Repository::getSerialNumber() - "
                     + "- rec is null!" );
            throw new EBaseException( "rec is null" );
        }

        BigInteger serial = rec.getSerialNumber();

        if (!mInit) {
            // cms may crash after issue a cert but before update 
            // the serial number record
            try {
                IDBObj obj = s.read("cn=" +
                        serial + "," + mBaseDN);

                if (obj != null) {
                    serial = serial.add(BI_ONE);
                    setSerialNumber(serial);
                }
            }catch (EBaseException e) {
                // do nothing
            }
            mInit = true;
        }
        return serial;
    }

    /**
     * Updates the serial number to the specified in db.
     * <P>
     *
     * @param num serial number
     */
    private void setSerialNumber(BigInteger num) throws EBaseException {
        IDBSSession s = mDB.createSession();

        CMS.debug("Repository:setSerialNumber " +  num.toString());

        return;

    }

    public String getMaxSerial() {
        return mMaxSerial;
    }

    public void setMaxSerial(String serial) throws EBaseException {
        BigInteger maxSerial = null;

        CMS.debug("Repository:setMaxSerial " + serial);

        return;
    }

    /**
     * init serial number cache
     */
    private void initCache() throws EBaseException {
        mNext = getSerialNumber();
        BigInteger serialConfig = new BigInteger("0");

        int radix = 10;
        
        CMS.debug("Repository: in InitCache");
        String minSerial = mDB.getMinSerialConfig();
        String maxSerial = mDB.getMaxSerialConfig();
        String minRequest = mDB.getMinRequestConfig();
        String maxRequest = mDB.getMaxRequestConfig();

        CMS.debug("Repository: minSerial " + minSerial + " maxSerial: " + maxSerial + " minRequest " + minRequest + " maxRequest " + maxRequest);

        if (this instanceof ICertificateRepository) {

            mMaxSerial = maxSerial;
            mMinSerial = minSerial;
            radix = 16;
            CMS.debug("Repository: Instance of Certificate Repository.");
        }  else  {

            if(this instanceof IKeyRepository)  {

                mMaxSerial = maxSerial;
                mMinSerial = minSerial;
                radix = 16;
                CMS.debug("Repository: Instance of Key Repository.");

            }  else {     // request repository

                mMaxSerial = maxRequest;
                mMinSerial = minRequest;
                radix = 10;
                CMS.debug("Repository: Instance of Request Repository.");

            }
        }

        if(mMinSerial != null) 
            mMinSerialNo = new BigInteger(mMinSerial,radix);

        if(mMaxSerial != null)
            mMaxSerialNo = new BigInteger(mMaxSerial,radix); 

        BigInteger theSerialNo = null;
        theSerialNo = getLastSerialNumberInRange(mMinSerialNo,mMaxSerialNo);

        if(theSerialNo != null)  {

            mLastSerialNo = new BigInteger(theSerialNo.toString());
            CMS.debug("Repository:  mLastSerialNo: " + mLastSerialNo.toString());

        }
        else  {

            throw new EBaseException("Error in obtaining the last serial number in the repository!");

        }

    }
   
    /**
     * get the next serial number in cache
     */
    public BigInteger getTheSerialNumber() throws EBaseException {
        
        CMS.debug("Repository:In getTheSerialNumber " );
        if (mLastSerialNo == null) 
            initCache();
        BigInteger serial = new BigInteger((mLastSerialNo.add(BI_ONE)).toString());

        if (mMaxSerialNo != null && serial.compareTo(mMaxSerialNo) > 0)
            return null;
        else
            return serial;
    }

    /**
     * Updates the serial number to the specified in db and cache.
     * <P>
     *
     * @param num serial number
     */
    public void setTheSerialNumber(BigInteger num) throws EBaseException {
        // mSerialNo is already set. But just in case

        CMS.debug("Repository:In setTheSerialNumber " + num.toString());

        if (mLastSerialNo == null)
            initCache();

        if (num.compareTo(mSerialNo) <= 0) {
            throw new EDBException(CMS.getUserMessage("CMS_DBS_SETBACK_SERIAL",
                    mSerialNo.toString(16)));
        }
        // write the config parameter. It's needed in case the serialNum gap
        // < BI_INCREMENT and server restart right afterwards.
        mDB.setNextSerialConfig(num);

        mSerialNo = num.subtract(BI_ONE);
        mNext = num.add(BI_INCREMENT);
        setSerialNumber(mNext);
    }

    /**
     * Retrieves the next serial number, and also increase the
     * serial number by one.
     * <P>
     *
     * @return serial number
     */
    public synchronized BigInteger getNextSerialNumber() throws
            EBaseException {

        CMS.debug("Repository: in getNextSerialNumber. ");
        if (mLastSerialNo == null) {
            initCache();

            mLastSerialNo = mLastSerialNo.add(BI_ONE);
            
          
        } else {
            mLastSerialNo = mLastSerialNo.add(BI_ONE);
        }

        if( mLastSerialNo == null ) {
            CMS.debug( "Repository::getNextSerialNumber() " +
                       "- mLastSerialNo is null!" );
            throw new EBaseException( "mLastSerialNo is null" );
        } else if( mLastSerialNo.compareTo( mMaxSerialNo ) > 0 ) {
            mLastSerialNo = mLastSerialNo.subtract(BI_ONE);
            throw new EDBException(CMS.getUserMessage("CMS_DBS_LIMIT_REACHED", 
                    mLastSerialNo.toString()));
        }

        BigInteger retSerial = new BigInteger(mLastSerialNo.toString());

        CMS.debug("Repository: getNextSerialNumber: returning retSerial " + retSerial);
        return retSerial; 
    }

    public abstract BigInteger getLastSerialNumberInRange(BigInteger  serial_low_bound, BigInteger serial_upper_bound) throws
       EBaseException;
}
