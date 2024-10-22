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

import java.math.BigInteger;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.DatabaseConfig;

/**
 * A class represents a replica repository. It
 * creates unique managed replica IDs.
 * <P>
 *
 * @author alee
 * @version $Revision$, $Date$
 */
public class ReplicaIDRepository extends Repository {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ReplicaIDRepository.class);

    /**
     * Constructs a certificate repository.
     */
    public ReplicaIDRepository(DBSubsystem dbSubsystem) {
        super(dbSubsystem, DEC);
    }

    @Override
    public void init() throws Exception {

        logger.info("ReplicaIDRepository: Initializing replica ID repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = dbConfig.getReplicaDN() + "," + dbSubsystem.getBaseDN();
        logger.info("ReplicaIDRepository: - base DN: " + mBaseDN);

        rangeDN = dbConfig.getReplicaRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("ReplicaIDRepository: - range DN: " + rangeDN);

        mMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.MIN_REPLICA_NUMBER, null);
        logger.info("ReplicaIDRepository: - min serial: " + mMinSerialNo);

        mMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.MAX_REPLICA_NUMBER, null);
        logger.info("ReplicaIDRepository: - max serial: " + mMaxSerialNo);

        String nextMinSerial = dbConfig.getNextBeginReplicaNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MIN_REPLICA_NUMBER, null);
        }
        logger.info("ReplicaIDRepository: - next min serial: " + mNextMinSerialNo);

        String nextMaxSerial = dbConfig.getNextEndReplicaNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = dbConfig.getBigInteger(DatabaseConfig.NEXT_MAX_REPLICA_NUMBER, null);
        }
        logger.info("ReplicaIDRepository: - next max serial: " + mNextMaxSerialNo);

        mLowWaterMarkNo = dbConfig.getBigInteger(DatabaseConfig.REPLICA_LOW_WATER_MARK, null);
        logger.debug("ReplicaIDRepository: - low water mark serial: " + mNextMaxSerialNo);

        mIncrementNo = dbConfig.getBigInteger(DatabaseConfig.REPLICA_INCREMENT, null);
        logger.debug("ReplicaIDRepository: - increment serial: " + mIncrementNo);
    }

    public void setMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMinSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("ReplicaIDRepository: Setting min serial number: " + serial);
        dbConfig.setBeginReplicaNumber(serial);
    }

    public void setMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();
        String serial = mMaxSerialNo.toString(mRadix);
        if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
           serial = "0x" + serial;
        }
        logger.debug("ReplicaIDRepository: Setting max serial number: " + serial);
        dbConfig.setEndReplicaNumber(serial);
    }

    public void setNextMinSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMinSerialNo == null) {
            logger.debug("ReplicaIDRepository: Removing next min number");
            dbConfig.removeNextBeginReplicaNumber();

        } else {
            String serial = mNextMinSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("ReplicaIDRepository: Setting next min number: " + serial);
            dbConfig.setNextBeginReplicaNumber(serial);
        }
    }

    public void setNextMaxSerialConfig() throws EBaseException {

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        if (mNextMaxSerialNo == null) {
            logger.debug("ReplicaIDRepository: Removing next max number");
            dbConfig.removeNextEndReplicaNumber();

        } else {
            String serial = mNextMaxSerialNo.toString(mRadix);
            if (mRadix == HEX && idGenerator == IDGenerator.LEGACY_2) {
               serial = "0x" + serial;
            }
            logger.debug("ReplicaIDRepository: Setting next max number: " + serial);
            dbConfig.setNextEndReplicaNumber(serial);
        }
    }

    /**
     * Returns last serial number in given range
     */
    @Override
    public BigInteger getLastSerialNumberInRange(BigInteger serial_low_bound, BigInteger serial_upper_bound)
            throws EBaseException {
        logger.debug("ReplicaIDReposoitory: in getLastSerialNumberInRange: low "
                + serial_low_bound + " high " + serial_upper_bound);
        if (serial_low_bound == null
                || serial_upper_bound == null || serial_low_bound.compareTo(serial_upper_bound) >= 0) {
            return null;
        }
        BigInteger ret = getMinSerial();
        if ((ret == null) || (ret.compareTo(serial_upper_bound) > 0) || (ret.compareTo(serial_low_bound) < 0)) {
            return null;
        }
        return ret;
    }
}
