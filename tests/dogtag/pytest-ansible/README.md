
# Environment-Setup Instructions

## Installing pip

[pip] (https://pip.pypa.io/en/stable/installing/)  is needed for ansible & pytest installation.

## Installing Supporting Packages

Install the pip and run requirements.txt file

```
pip install -r requirements.txt
```

## Installing CA, KRA, OCSP, TKS & TPS Subsystems

Refer [README.md] (installation/README.md)



## Running Pytest-Ansible test cases.

### Pre-requisite

* Run role user setup for creating different users for subsystems which includes
  setting up Valid, Revoked, UnTrusted and Expired certificates.

  * To do this you need to install the pki.testlib using setup.py.

        Once you clone the repo run the following command from the setup.py directory. `pip install .`

        This will install pki.testlib and it's dependencies

        Once that is done you can use pki.testlib to run a sanity test [here] (pytest/sanity/test_role_users.py)

        This sanity test uses pytest test_setup method construct to run role user setup part before rest of the automation runs.

  * You can also use role user creation code in your tests.

        ```python
        cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host='pki1.example.com',
                               port=constants.CA_HTTP_PORT,
                               nick="'{}'".format(constants.CA_ADMIN_NICK))
        cert_setup.create_certdb(ansible_module)
        cert_setup.import_ca_cert(ansible_module)
        cert_setup.import_admin_p12(ansible_module, 'ca')
        cert_setup.setup_role_users(ansible_module, 'ca', constants.CA_ADMIN_NICK, duration='minute')
        ```

        constants.py contains all the variables required in role user creation.

        For example:

         - constants.NSSDB

         - constants.CA_HTTP_PORT

        Here CertSetup object is used to create role users.

        CertSetup takes the following parameters

        ```
        nssdb: <nssdb_path>
        db_pass: <nssdb_password>
        host: <hostname_on_which_tests_are_run>
        port: <subsystem_http_port>
        nick: <subsystem_admin_nickname>
        ```

  * Once the CertSetup object is created it can be used to call the remaining methods for role user setup namely,

      - creating certdb (create_certdb method) This method takes ansible_module as a parameter

      - importing CA Cert (import_ca_cert method) This method takes ansible_module as a parameter

      - importing admin p12 (import_admin_p12) This method takes ansible_module and subsystem as a parameter

      - setup role users (setup_role_users method) This method takes ansible_module, subsystem admin nickname
      and duration as a parameter. Here duration is used for creating a profile for expired certificates which are valid for only 1 minute.

  * Just like we can setup role users for CA subsystem we can also create role users for other subsystems. One thing to note here is that before creating role users for KRA/OCSP/TKS/TPS you need to create CA role users first since it involves profile creation

        Here is a snippet to create role users for TPS subsystem

        ```python
        cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host='pki1.example.com',
                               port=constants.CA_HTTP_PORT,
                               nick="'{}'".format(constants.CA_ADMIN_NICK))
        tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                                   db_pass=constants.CLIENT_DATABASE_PASSWORD,
                                   host='pki1.example.com',
                                   port=constants.TPS_HTTP_PORT,
                                   nick="'{}'".format(constants.TPS_ADMIN_NICK))
        cert_setup.create_certdb(ansible_module)
        cert_setup.import_ca_cert(ansible_module)
        cert_setup.import_admin_p12(ansible_module, 'ca')
        cert_setup.setup_role_users(ansible_module, 'ca', constants.CA_ADMIN_NICK, duration='minute')
        tps_cert_setup.import_admin_p12(ansible_module, 'tps')
        tps_cert_setup.setup_role_users(ansible_module, 'tps', constants.TPS_ADMIN_NICK,
                                        constants.TPS_HTTP_PORT,
                                        constants.CA_ADMIN_NICK, duration='minute')
        ```

        Here we need to create a separate CertSetup object for TPS subsystem since it has different subsystem config values.

        Please refer [test_role_users.py] (pytest/sanity/test_role_users.py) for a set of sanity tests with role users.

* Refer [README.md] (pytest/README.md)
