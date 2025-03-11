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

#include <jni.h>

#include "main/NameValueSet.h"
#include "main/RA_Client.h"

void
throwCLIException(JNIEnv* env, const char* message) {
    jclass clazz = env->FindClass("org/dogtagpki/cli/CLIException");
    env->ThrowNew(clazz, message);
}

NameValueSet*
convertParams(JNIEnv* env, jobject params) {

    // Map
    jclass mapClass = env->FindClass("java/util/Map");
    jmethodID keySetMethod = env->GetMethodID(
        mapClass,
        "keySet",
        "()Ljava/util/Set;");
    jmethodID getMethod = env->GetMethodID(
        mapClass,
        "get",
        "(Ljava/lang/Object;)Ljava/lang/Object;");

    // Set
    jclass setClass = env->FindClass("java/util/Set");
    jmethodID iteratorMethod = env->GetMethodID(
        setClass,
        "iterator",
        "()Ljava/util/Iterator;");

    // Iterator
    jclass iteratorClass = env->FindClass("java/util/Iterator");
    jmethodID hasNextMethod = env->GetMethodID(
        iteratorClass,
        "hasNext",
        "()Z");
    jmethodID nextMethod = env->GetMethodID(
        iteratorClass,
        "next",
        "()Ljava/lang/Object;");

    NameValueSet *set = new NameValueSet();

    // Set<String> keys = params.keySet();
    jobject keys = env->CallObjectMethod(params, keySetMethod);

    // Iterator<String> iterator = keys.iterator();
    jobject iterator = env->CallObjectMethod(keys, iteratorMethod);

    while (true) {
        // boolean hasNext = iterator.hasNext();
        jboolean hasNext = env->CallBooleanMethod(iterator, hasNextMethod);

        if (!hasNext) {
            break;
        }

        // String key = iterator.next();
        jstring key = (jstring) env->CallObjectMethod(iterator, nextMethod);

        // String value = params.get(key);
        jstring value = (jstring) env->CallObjectMethod(params, getMethod, key);

        char* ckey = (char*) env->GetStringUTFChars(key, NULL);
        char* cvalue = (char*) env->GetStringUTFChars(value, NULL);

        set->Add(ckey, cvalue);

        env->ReleaseStringUTFChars(value, cvalue);
        env->ReleaseStringUTFChars(key, ckey);
    }

    return set;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_createClient
(JNIEnv* env, jobject object) {
    RA_Client* client = new RA_Client();
    return (jlong) client;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_removeClient
(JNIEnv* env, jobject object, jlong client) {
    RA_Client* cclient = (RA_Client*) client;
    delete cclient;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_getOldStyle
(JNIEnv* env, jobject object, jlong client) {
    RA_Client* cclient = (RA_Client*) client;
    return cclient->old_style == PR_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setOldStyle
(JNIEnv* env, jobject object, jlong client, jboolean value) {
    RA_Client* cclient = (RA_Client*) client;
    cclient->old_style = value ? PR_TRUE : PR_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_displayHelp
(JNIEnv* env, jobject object, jlong client) {

    RA_Client* cclient = (RA_Client*) client;
    int status = cclient->OpHelp(NULL);

    if (status == 0) {
        throwCLIException(env, "Unable to display help");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_performFormatToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;

    ThreadArg arg;
    arg.time = 0;
    arg.status = 0;
    arg.client = cclient;
    arg.token = cclient->m_token.Clone();
    arg.params = convertParams(env, params);

    ThreadConnUpdate(&arg);

    delete arg.params;
    delete arg.token;

    if (arg.status == 0) {
        throwCLIException(env, "Unable to format token");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_newFormatToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpConnStart(set, OP_CLIENT_FORMAT);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to format token");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_resetPIN
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status;
    if (cclient->old_style) {
        status = cclient->OpConnResetPin(set);
    } else {
        status = cclient->OpConnStart(set, OP_CLIENT_RESET_PIN);
    }

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to reset PIN");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_enrollToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status;
    if (cclient->old_style) {
        status = cclient->OpConnEnroll(set);
    } else {
        status = cclient->OpConnStart(set, OP_CLIENT_ENROLL);
    }

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to enroll token");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_displayToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpTokenStatus(set);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to display token");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setupToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpTokenSet(set);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to set up token");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setupDebug
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarDebug(set);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to set up debug");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setVariable
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarSet(set);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to set variable");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_displayVariable
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarGet(set);

    delete set;

    if (status == 0) {
        throwCLIException(env, "Unable to display variable");
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_listVariables
(JNIEnv* env, jobject object, jlong client) {

    RA_Client* cclient = (RA_Client*) client;
    int status = cclient->OpVarList(NULL);

    if (status == 0) {
        throwCLIException(env, "Unable to list variables");
    }
}
