#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/..
mvn -q -ff clean package || { echo 'build failed' ; exit -1; }
TMP=target/integ_test_tmp
rm -rf $TMP
mkdir -p $TMP
cd $TMP
wget https://download.elasticsearch.org/elasticsearch/release/org/elasticsearch/distribution/tar/elasticsearch/2.0.0/elasticsearch-2.0.0.tar.gz
tar -xzf elasticsearch-2.0.0.tar.gz
cd elasticsearch-2.0.0
bin/plugin install license
bin/plugin install shield
bin/shield/syskeygen
bin/plugin remove elasticsearch-shield-kerberos-realm 
bin/plugin install file:///$DIR/../target/releases/elasticsearch-shield-kerberos-realm-2.0.0.zip
echo "shield.authc.realms.kerb.type: cc-kerberos" > config/elasticsearch.yml
echo "shield.authc.realms.kerb.order: 0"  >> config/elasticsearch.yml
echo "shield.authc.realms.kerb.acceptor_keytab_path: $DIR/../../kerby-dist/kdc-dist-1.0.0-RC1/http.keytab"  >> config/elasticsearch.yml
echo "shield.authc.realms.kerb.acceptor_principal: HTTP/localhost@EXAMPLE.COM"  >> config/elasticsearch.yml
echo "shield.authc.realms.kerb.roles: admin"  >> config/elasticsearch.yml
echo "de.codecentric.realm.cc-kerberos.krb5.file_path: $DIR/../../kerby-dist/kdc-dist-1.0.0-RC1/conf/krb5.conf" >> config/elasticsearch.yml
echo "de.codecentric.realm.cc-kerberos.krb_debug: true" >> config/elasticsearch.yml
echo "security.manager.enabled: false" >> config/elasticsearch.yml
cat config/elasticsearch.yml
bin/elasticsearch

