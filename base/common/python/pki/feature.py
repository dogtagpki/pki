# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2014 Red Hat, Inc.
# All rights reserved.
#
# Author:
#     Ade Lee <alee@redhat.com>

import inspect
import json
import logging

from six import iteritems

import pki
import pki.client as client
import pki.encoder as encoder

logger = logging.getLogger(__name__)


class Feature(object):
    """Class containing data about Features advertised by the CS server
    """

    json_attribute_names = {
        'id': 'feature_id',
        'description': 'description',
        'enabled': 'enabled',
        'version': 'version'
    }

    def __init__(self, feature_id=None, version=None, description=None,
                 enabled="False"):
        self.feature_id = feature_id
        self.version = version
        self.description = description
        self.enabled = (enabled.lower() == "true")

    def __repr__(self):
        attributes = {
            "Feature": {
                "feature_id": self.feature_id,
                "description": self.description,
                "version": self.version,
                "enabled": self.enabled
            }
        }
        return str(attributes)

    @classmethod
    def from_json(cls, attr_list):
        """ Return Feature object from JSON dict """
        feature = cls()

        for k, v in iteritems(attr_list):
            if k in Feature.json_attribute_names:
                setattr(feature, Feature.json_attribute_names[k], v)
            else:
                setattr(feature, k, v)

        return feature


class FeatureCollection(object):
    """
    Class containing list of Feature objects.
    This data is returned when listing features.
    """

    def __init__(self):
        """ Constructor """
        self.feature_list = []
        self.links = []

    def __iter__(self):
        return iter(self.feature_list)

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        features = json_value
        if not isinstance(features, list):
            ret.feature_list.append(Feature.from_json(features))
        else:
            for feature in features:
                ret.feature_list.append(
                    Feature.from_json(feature))

        return ret


class FeatureClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    AuthorityResource Java interface class defining the REST API for
    subordinate CA (authority) resources.
    """

    def __init__(self, parent):
        """ Constructor """

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in FeatureClient.__init__() '
                'has been deprecated. Provide SubsystemClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.subsystem_client = None
            self.pki_client = None
            self.connection = parent

        else:
            self.subsystem_client = parent
            self.pki_client = self.subsystem_client.parent
            self.connection = self.pki_client.connection

        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}

    @pki.handle_exceptions()
    def get_feature(self, feature_id):
        """ Return a Feature object. """
        if feature_id is None:
            raise ValueError("Feature ID must be specified")

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'rest'

        path = '/%s/config/features/%s' % (api_path, feature_id)

        if not self.connection.subsystem:
            path = '/ca' + path

        response = self.connection.get(path, self.headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return Feature.from_json(json_response)

    @pki.handle_exceptions()
    def list_features(self):
        """ Return a FeatureCollection object of all available features
        """

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'rest'

        path = '/%s/config/features' % api_path

        if not self.connection.subsystem:
            path = '/ca' + path

        response = self.connection.get(
            path=path,
            headers=self.headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return FeatureCollection.from_json(json_response)


encoder.NOTYPES['Feature'] = Feature


def main():
    # Create a PKIConnection object that stores the details of the CA.
    connection = client.PKIConnection('https', 'localhost', '8453')

    # Instantiate the FeatureClient
    feature_client = FeatureClient(connection)

    # List all features
    print("Listing all features")
    print("-----------------------")
    features = feature_client.list_features()
    for feature in features.feature_list:
        print(str(feature))

    # Get authority feature
    print("Getting authority feature")
    print("-------------------------")
    feature = feature_client.get_feature("authority")
    print(str(feature))

    # Get non-existent feature
    print("Get non-existent feature")
    print("------------------------")
    try:
        feature_client.get_feature("foobar")
    except pki.ResourceNotFoundException as e:
        print(e.message)


if __name__ == "__main__":
    main()
