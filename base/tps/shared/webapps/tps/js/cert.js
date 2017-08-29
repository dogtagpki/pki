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
            userID: response.UserID,
            tokenID: response.TokenID,
            origin: response.Origin,
            type: response.Type,
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
            UserID: attributes.userID,
            TokenID: attributes.tokenID,
            Origin: attributes.origin,
            Type: attributes.type,
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
            userID: entry.UserID,
            tokenID: entry.TokenID,
            origin: entry.Origin,
            type: entry.Type,
            keyType: entry.KeyType,
            status: entry.Status,
            createTime: entry.CreateTime,
            modifyTime: entry.ModifyTime
        });
    }
});

var CertificatePage = EntryPage.extend({
    initialize: function(options) {
        var self = this;
        CertificatePage.__super__.initialize.call(self, options);
    }
});

var CertificatesTable = ModelTable.extend({
    initialize: function(options) {
        var self = this;
        CertificatesTable.__super__.initialize.call(self, options);
    }
});

var CertificatesPage = Page.extend({
    load: function() {
        var self = this;

        if (self.collection && self.collection.options && self.collection.options.tokenID) {
            $(".pki-breadcrumb-tokens").show();
            $(".pki-breadcrumb-token a")
                .attr("href", "#tokens/" + self.collection.options.tokenID)
                .text("Token " + self.collection.options.tokenID);
            $(".pki-breadcrumb-token").show();
            $(".pki-title").text("Certificates for Token " + self.collection.options.tokenID);
        }

        var table = new CertificatesTable({
            el: $("table[name='certificates']"),
            collection: self.collection
        });

        table.render();
    }
});
