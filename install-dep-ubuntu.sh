#!/usr/bin/env bash

sudo apt-get update
sudo apt-get install -y automake cmake build-essential libprocps-dev libtool\
                        pkg-config yasm texinfo autoconf flex bison

sudo apt-get install gcc-7 g++-7