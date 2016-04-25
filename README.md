Shield Kerberos Realm
=====================

[![Build Status](https://travis-ci.org/codecentric/elasticsearch-shield-kerberos-realm.svg?branch=master)](https://travis-ci.org/codecentric/elasticsearch-shield-kerberos-realm)
[![Coverage Status](https://coveralls.io/repos/codecentric/elasticsearch-shield-kerberos-realm/badge.svg?branch=master&service=github)](https://coveralls.io/github/codecentric/elasticsearch-shield-kerberos-realm?branch=master)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

Kerberos/SPNEGO custom realm for Elasticsearch Shield 2.3.1.  
Authenticate HTTP and Transport requests via Kerberos/SPNEGO.

###License
Apache License Version 2.0

###Features

* Kerberos/SPNEGO REST/HTTP authentication
* Kerberos/SPNEGO Transport authentication
* No JAAS login.conf required
* No external dependencies

###Community support
[Stackoverflow](http://stackoverflow.com/questions/ask?tags=es-kerberos+elasticsearch)  
[Twitter @hendrikdev22](https://twitter.com/hendrikdev22)

###Commercial support
Available. Please contact [vertrieb@codecentric.de](mailto:vertrieb@codecentric.de)

###Prerequisites

* Elasticsearch 2.3.1
* Shield Plugin 2.3.1
* Kerberos Infrastructure (ActiveDirectory, MIT, Heimdal, ...)

###Install release
[Download latest release](https://github.com/codecentric/elasticsearch-shield-kerberos-realm/releases) and store it somewhere. Then execute:

    $ bin/plugin install file:///path/to/target/release/elasticsearch-shield-kerberos-realm-2.3.1.zip

###Build and install latest
    $ git clone https://github.com/codecentric/elasticsearch-shield-kerberos-realm.git
    $ mvn package
    $ bin/plugin install file:///path/to/target/release/elasticsearch-shield-kerberos-realm-2.3.1.zip

###Configuration

Configuration is done in elasticsearch.yml

    shield.authc.realms.cc-kerberos.type: cc-kerberos
    shield.authc.realms.cc-kerberos.order: 0
    shield.authc.realms.cc-kerberos.acceptor_keytab_path: /path/to/server.keytab
    shield.authc.realms.cc-kerberos.acceptor_principal: HTTP/localhost@REALM.COM
    shield.authc.realms.cc-kerberos.roles: role1, role2
    shield.authc.realms.cc-kerberos.strip_realm_from_principal: true
    de.codecentric.realm.cc-kerberos.krb5.file_path: /etc/krb5.conf
    de.codecentric.realm.cc-kerberos.krb_debug: false
    security.manager.enabled: false

* ``acceptor_keytab_path`` - The absolute path to the keytab where the acceptor_principal credentials are stored.
* ``acceptor_principal`` - Acceptor (Server) Principal name, must be present in acceptor_keytab_path file
* ``roles`` - Roles which should be assigned to the initiator (the user who's logged in)
* ``strip_realm_from_principal`` - If true then the realm will be stripped from the user name
* ``de.codecentric.realm.cc-kerberos.krb_debug`` - If true a whole bunch of kerberos/security related debugging output will be logged to standard out
* ``de.codecentric.realm.cc-kerberos.krb5.file_path`` - Absolute path to krb5.conf file.
* ``security.manager.enabled`` - Must currently be set to ``false``. This will likely change with Elasticsearch 2.2, see [PR 14108](https://github.com/elastic/elasticsearch/pull/14108)


###REST/HTTP authentication

    $ kinit
    $ curl --negotiate -u : "http://localhost:9200/_logininfo?pretty"

Or with a browser that supports SPNEGO like Chrome or Firefox

###Transport authentication

    try (TransportClient client = TransportClient.builder().settings(settings).build()) {
        client.addTransportAddress(nodes[0].getTransport().address().publishAddress());
            try (KerberizedClient kc = new KerberizedClient(client,
                                            "user@REALM.COM",
                                            "secret",
                                            "HTTP/localhost@REALM.COM")) {

                ClusterHealthResponse response = kc.admin().cluster().prepareHealth().execute().actionGet();
                assertThat(response.isTimedOut(), is(false));
            }
    }

####Login with password
    KerberizedClient kc = new KerberizedClient(client,
                                            "user@REALM.COM",
                                            "secret",
                                            "HTTP/localhost@REALM.COM")

####Login with (client side) keytab
    KerberizedClient kc = new KerberizedClient(client,
                                            Paths.get("client.keytab"),
                                            "user@REALM.COM",
                                            "HTTP/localhost@REALM.COM")

####Login with TGT (Ticket)
    KerberizedClient kc = new KerberizedClient(client,
                                            "user@REALM.COM",
                                             Paths.get("ticket.cc"),
                                            "HTTP/localhost@REALM.COM")    

####Login with javax.security.auth.Subject
    KerberizedClient kc = new KerberizedClient(client,
                                             subject,
                                            "HTTP/localhost@REALM.COM")    
