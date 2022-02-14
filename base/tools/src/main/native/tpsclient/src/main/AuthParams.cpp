// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "authentication/AuthParams.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

TPS_PUBLIC AuthParams::AuthParams () {
}

/**
 * Destructs processor.
 */
AuthParams::~AuthParams () {
}

TPS_PUBLIC void AuthParams::SetUID(char *uid) {
    Add("UID", uid);
}

TPS_PUBLIC char *AuthParams::GetUID() {
    return GetValue("UID");
}

TPS_PUBLIC void AuthParams::SetPassword(char *pwd) {
    Add("PASSWORD", pwd);
}

TPS_PUBLIC char *AuthParams::GetPassword() {
    return GetValue("PASSWORD");
}

void AuthParams::SetSecuridValue(char *securidValue) {
    Add("SECURID_VALUE", securidValue);
}

TPS_PUBLIC char *AuthParams::GetSecuridValue() {
    return GetValue("SECURID_VALUE");
}

void AuthParams::SetSecuridPin(char *securidPin) {
    Add("SECURID_PIN", securidPin);
}

TPS_PUBLIC char *AuthParams::GetSecuridPin() {
    return GetValue("SECURID_PIN");
}

