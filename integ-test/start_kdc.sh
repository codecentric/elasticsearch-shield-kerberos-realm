#!/bin/sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR/../..
git clone https://github.com/salyh/kerby-dist
cd $DIR/..
rm -rf target/kdc_work/
mkdir -p target/kdc_work
cd ../kerby-dist/kdc-dist-1.0.0-RC1
echo "Start KDC, logs are here $(pwd)/logs"
./bin/start-kdc.sh conf/ $DIR/../target/kdc_work