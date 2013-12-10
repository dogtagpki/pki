/* --- BEGIN COPYRIGHT BLOCK ---
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * --- END COPYRIGHT BLOCK ---
 *
 * @author Endi S. Dewata
 */

var CertificateModel = Model.extend({
    urlRoot: "/tps/rest/certs",
    parseResponse: function(response) {
        return {
            id: response.Certificate["@id"],
            serialNumber: response.Certificate.SerialNumber,
            subject: response.Certificate.Subject,
            tokenID: response.Certificate.TokenID,
            userID: response.Certificate.UserID,
            keyType: response.Certificate.KeyType,
            status: response.Certificate.Status,
            createTime: response.Certificate.CreateTime,
            modifyTime: response.Certificate.ModifyTime
        };
    },
    createRequest: function(attributes) {
        return {
            Certificate: {
                "@id": attributes.id,
                SerialNumber: attributes.serialNumber,
                Subject: attributes.subject,
                TokenID: attributes.tokenID,
                UserID: attributes.userID,
                KeyType: attributes.keyType,
                Status: attributes.status,
                CreateTime: CreateTimeattributes.createTime,
                ModifyTime: attributes.modifyTime
            }
        };
    }
});

var CertificateCollection = Collection.extend({
    urlRoot: "/tps/rest/certs",
    getEntries: function(response) {
        return response.Certificates.Certificate;
    },
    getLinks: function(response) {
        return response.Certificates.Link;
    },
    parseEntry: function(entry) {
        return new CertificateModel({
            id: entry["@id"],
            serialNumber: entry.SerialNumber,
            subject: entry.Subject,
            tokenID: entry.TokenID,
            userID: entry.UserID,
            keyType: entry.KeyType,
            status: entry.Status,
            createTime: entry.CreateTime,
            modifyTime: entry.ModifyTime
        });
    }
});
