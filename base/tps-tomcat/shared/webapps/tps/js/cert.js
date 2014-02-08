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
            id: response.id,
            serialNumber: response.SerialNumber,
            subject: response.Subject,
            tokenID: response.TokenID,
            userID: response.UserID,
            keyType: response.KeyType,
            status: response.Status,
            createTime: response.CreateTime,
            modifyTime: response.ModifyTime
        };
    },
    createRequest: function(attributes) {
        return {
            id: attributes.id,
            SerialNumber: attributes.serialNumber,
            Subject: attributes.subject,
            TokenID: attributes.tokenID,
            UserID: attributes.userID,
            KeyType: attributes.keyType,
            Status: attributes.status,
            CreateTime: attributes.createTime,
            ModifyTime: attributes.modifyTime
        };
    }
});

var CertificateCollection = Collection.extend({
    urlRoot: "/tps/rest/certs",
    getEntries: function(response) {
        return response.entries;
    },
    getLinks: function(response) {
        return response.Link;
    },
    parseEntry: function(entry) {
        return new CertificateModel({
            id: entry.id,
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

var CertificatePage = Page.extend({
    load: function() {
        var editDialog = new Dialog({
            el: $("#certificate-dialog"),
            title: "Edit Certificate",
            readonly: ["id", "serialNumber", "subject", "tokenID", "userID",
            "keyType", "status", "createTime", "modifyTime"]
        });

        new Table({
            el: $("table[name='certificates']"),
            collection: new CertificateCollection({ size: 3 }),
            editDialog: editDialog
        });
    }
});
