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
        super(dbSubsystem, 10);
    }

    @Override
    public void init() throws Exception {

        logger.info("ReplicaIDRepository: Initializing replica ID repository");

        DatabaseConfig dbConfig = dbSubsystem.getDBConfigStore();

        mBaseDN = dbConfig.getReplicaDN() + "," + dbSubsystem.getBaseDN();
        logger.info("ReplicaIDRepository: - base DN: " + mBaseDN);

        rangeDN = dbConfig.getReplicaRangeDN() + "," + dbSubsystem.getBaseDN();
        logger.info("ReplicaIDRepository: - range DN: " + rangeDN);

        minSerialName = DatabaseConfig.MIN_REPLICA_NUMBER;
        String minSerial = dbConfig.getBeginReplicaNumber();
        if (minSerial != null) {
            mMinSerialNo = new BigInteger(minSerial, mRadix);
        }
        logger.info("ReplicaIDRepository: - min serial: " + mMinSerialNo);

        maxSerialName = DatabaseConfig.MAX_REPLICA_NUMBER;
        String maxSerial = dbConfig.getEndReplicaNumber();
        if (maxSerial != null) {
            mMaxSerialNo = new BigInteger(maxSerial, mRadix);
        }
        logger.info("ReplicaIDRepository: - max serial: " + mMaxSerialNo);

        nextMinSerialName = DatabaseConfig.NEXT_MIN_REPLICA_NUMBER;
        String nextMinSerial = dbConfig.getNextBeginReplicaNumber();
        if (nextMinSerial == null || nextMinSerial.equals("-1")) {
            mNextMinSerialNo = null;
        } else {
            mNextMinSerialNo = new BigInteger(nextMinSerial, mRadix);
        }
        logger.info("ReplicaIDRepository: - next min serial: " + mNextMinSerialNo);

        nextMaxSerialName = DatabaseConfig.NEXT_MAX_REPLICA_NUMBER;
        String nextMaxSerial = dbConfig.getNextEndReplicaNumber();
        if (nextMaxSerial == null || nextMaxSerial.equals("-1")) {
            mNextMaxSerialNo = null;
        } else {
            mNextMaxSerialNo = new BigInteger(nextMaxSerial, mRadix);
        }
        logger.info("ReplicaIDRepository: - next max serial: " + mNextMaxSerialNo);

        String lowWaterMark = dbConfig.getReplicaLowWaterMark();
        if (lowWaterMark != null) {
            mLowWaterMarkNo = new BigInteger(lowWaterMark, mRadix);
        }

        String incrementNo = dbConfig.getReplicaIncrement();
        if (incrementNo != null) {
            mIncrementNo = new BigInteger(incrementNo, mRadix);
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
