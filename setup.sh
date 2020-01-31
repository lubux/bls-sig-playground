#!/usr/bin/env bash

git clone https://github.com/skalenetwork/libBLS.git
cd libBLS
git checkout f5b49d775b29a28ea2087b02cc88e8491760a189
cd deps
./build.sh
cd ..
cmake -H. -Bbuild
cmake --build build
cd ..