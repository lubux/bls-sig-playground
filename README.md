# BLS-Signature Playground

[![Build status](https://travis-ci.org/lubux/bls-sig-playground.svg?branch=master)](https://travis-ci.org/lubux/bls-sig-playground)

## Overview 
This repository implements a small demo use-case of BLS threshold signatures. 
We consider a scenario where a small company has perform payments to suplliers at the end of each month.
The payments have to be approved by a subset of the board to be accepted. 

In this repository we demonstrate an example on how to automate this process with threshold signatures. 
Each member posses a BLS threshold signature private key, which can be used to sign payments with a BLS signature.
The payment will be accepted by the verifier if upto `t` members have signed the payment request.
The verifier should only accept the payment if the signature can be verified 

## Dependencies 
The code relies on the BLS threshold signature implementation from the [libBLS](https://github.com/skalenetwork/libBLS) library.

## Building the Dependencies 
See  [libBLS](https://github.com/skalenetwork/libBLS) for the basic requirements.

Example for Ubuntu 
```bash
sudo apt-get update
sudo apt-get install -y automake cmake build-essential libprocps-dev libtool\
                        pkg-config yasm texinfo autoconf flex bison

```

To install and build the dependencies just run
```
bash ./setup.sh
```

## Installation

After running installation script for the dependencies, the following command has to be executed to build the project.
```
cmake . && make
``` 

## Running the Demo 

To start the non-interactive demo, run the `bin/requested_demo` executable.
The non-interactive demo consider 5 board members with a approval threshold of 3 and processes 50 payment requests.

To start the interactive console demo, run the `bin/demo_app` executable.
