#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export KRB5_CONFIG=$DIR/../../kerby-dist/kdc-dist-1.0.0-RC1/conf/krb5.conf
echo "Password is: lukepwd"
kinit luke@EXAMPLE.COM || { echo 'kinit failed' ; exit -1; }
curl -vvv --negotiate  -u : "http://localhost:9200/?pretty"
curl -vvv --negotiate  -u : "http://localhost:9200/_cluster/health?pretty"
curl -vvv --negotiate  -u : "http://localhost:9200/_logininfo?pretty"