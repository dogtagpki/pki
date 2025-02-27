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

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_createClient
(JNIEnv* env, jclass clazz) {
    RA_Client* client = new RA_Client();
    return (jlong) client;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_removeClient
(JNIEnv* env, jclass clazz, jlong client) {
    RA_Client* cclient = (RA_Client*) client;
    delete cclient;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscape_cmstools_tps_TPSClientCLI_invokeOperation
(JNIEnv* env, jclass clazz, jlong client, jstring op, jobject params) {

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

    RA_Client* cclient = (RA_Client*) client;
    char* cop = (char*) env->GetStringUTFChars(op, NULL);
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

    cclient->InvokeOperation(cop, set);

    env->ReleaseStringUTFChars(op, cop);
}
