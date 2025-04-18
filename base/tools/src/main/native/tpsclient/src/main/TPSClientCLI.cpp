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
#include <nspr.h>

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

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_createToken
(JNIEnv* env, jobject object, jlong client) {
    RA_Client* cclient = (RA_Client*) client;

    return (jlong) cclient->m_token.Clone();
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_removeToken
(JNIEnv* env, jobject object, jlong token) {
    RA_Token* ctoken = (RA_Token*) token;
    delete ctoken;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_createConnection
(JNIEnv* env, jobject object, jlong client) {
    RA_Client* cclient = (RA_Client*) client;

    char* hostname = cclient->m_vars.GetValue("ra_host");
    int port = atoi(cclient->m_vars.GetValue("ra_port"));
    char* uri = cclient->m_vars.GetValue("ra_uri");

    return (jlong) new RA_Conn(hostname, port, uri);
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_connect
(JNIEnv* env, jobject object, jlong connection) {
    RA_Conn* conn = (RA_Conn*) connection;

    if (!conn->Connect()) {
        char* hostname = conn->GetHostname();
        int port = conn->GetPort();
        char *message = PR_smprintf("Cannot connect to %s:%d", hostname, port);
        throwCLIException(env, message);
        PR_smprintf_free(message);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_disconnect
(JNIEnv* env, jobject object, jlong connection) {
    RA_Conn* conn = (RA_Conn*) connection;
    conn->Close();
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_removeConnection
(JNIEnv* env, jobject object, jlong connection) {
    RA_Conn* conn = (RA_Conn*) connection;
    delete conn;
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
(JNIEnv* env, jobject object, jlong client, jobject params, jobject exts, jlong token, jlong connection) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet* set = convertParams(env, params);
    NameValueSet* cexts = convertParams(env, exts);
    RA_Token* ctoken = (RA_Token*) token;
    RA_Conn* conn = (RA_Conn*) connection;

    int status = FormatToken(cclient, set, cexts, ctoken, conn);

    if (status == 0) {
        throwCLIException(env, "Unable to format token");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_performResetPIN
(JNIEnv* env, jobject object, jlong client, jobject params, jobject exts, jlong token, jlong connection) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet* set = convertParams(env, params);
    NameValueSet* cexts = convertParams(env, exts);
    RA_Token* ctoken = (RA_Token*) token;
    RA_Conn* conn = (RA_Conn*) connection;

    int status = ResetPIN(cclient, set, cexts, ctoken, conn);

    if (status == 0) {
        throwCLIException(env, "Unable to reset PIN");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_performEnrollToken
(JNIEnv* env, jobject object, jlong client, jobject params, jobject exts, jlong token, jlong connection) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet* set = convertParams(env, params);
    NameValueSet* cexts = convertParams(env, exts);
    RA_Token* ctoken = (RA_Token*) token;
    RA_Conn* conn = (RA_Conn*) connection;

    int status = EnrollToken(cclient, set, cexts, ctoken, conn);

    if (status == 0) {
        throwCLIException(env, "Unable to enroll token");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_displayToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpTokenStatus(set);

    if (status == 0) {
        throwCLIException(env, "Unable to display token");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setupToken
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpTokenSet(set);

    if (status == 0) {
        throwCLIException(env, "Unable to set up token");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setupDebug
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarDebug(set);

    if (status == 0) {
        throwCLIException(env, "Unable to set up debug");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_setVariable
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarSet(set);

    if (status == 0) {
        throwCLIException(env, "Unable to set variable");
    }

    delete set;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_displayVariable
(JNIEnv* env, jobject object, jlong client, jobject params) {

    RA_Client* cclient = (RA_Client*) client;
    NameValueSet *set = convertParams(env, params);

    int status = cclient->OpVarGet(set);

    if (status == 0) {
        throwCLIException(env, "Unable to display variable");
    }

    delete set;
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
