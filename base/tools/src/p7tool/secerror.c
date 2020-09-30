/** BEGIN COPYRIGHT BLOCK
 *
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * END COPYRIGHT BLOCK **/

/* Originally obtained from:
 * 
 *     CVSROOT=:pserver:anonymous@cvs-mirror.mozilla.org:/cvsroot
 *     cvs export -r NSS_3_11_3_RTM -N mozilla/security/nss/cmd/lib/secerror.c
 */

#include "nspr.h"
#include "secerror.h"

struct tuple_str {
    PRErrorCode	 errNum;
    const char * errString;
};

typedef struct tuple_str tuple_str;

#define ER2(a,b)   {a, b},
#define ER3(a,b,c) {a, c},

#include "secerr.h"
#include "sslerr.h"

const tuple_str errStrings[] = {

/* keep this list in asceding order of error numbers */
#include "SSLerrs.h"
#include "SECerrs.h"
#include "NSPRerrs.h"

};

const PRInt32 numStrings = sizeof(errStrings) / sizeof(tuple_str);

/* Returns a UTF-8 encoded constant error string for "errNum".
 * Returns NULL of errNum is unknown.
 */
const char *
SECU_Strerror(PRErrorCode errNum) {
    PRInt32 low  = 0;
    PRInt32 high = numStrings - 1;
    PRInt32 i;
    PRErrorCode num;
    static int initDone;

    /* make sure table is in ascending order.
     * binary search depends on it.
     */
    if (!initDone) {
	PRErrorCode lastNum = ((PRInt32)0x80000000);
    	for (i = low; i <= high; ++i) {
	    num = errStrings[i].errNum;
	    if (num <= lastNum) {
	    	fprintf(stderr, 
"sequence error in error strings at item %d\n"
"error %d (%s)\n"
"should come after \n"
"error %d (%s)\n",
		        i, lastNum, errStrings[i-1].errString, 
			num, errStrings[i].errString);
	    }
	    lastNum = num;
	}
	initDone = 1;
    }

    /* Do binary search of table. */
    while (low + 1 < high) {
    	i = (low + high) / 2;
	num = errStrings[i].errNum;
	if (errNum == num) 
	    return errStrings[i].errString;
        if (errNum < num)
	    high = i;
	else 
	    low = i;
    }
    if (errNum == errStrings[low].errNum)
    	return errStrings[low].errString;
    if (errNum == errStrings[high].errNum)
    	return errStrings[high].errString;
    return NULL;
}
