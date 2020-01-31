//
// Created by Lukas Burkhalter on 2020-01-31.
//

#ifndef THRESHOLD_SIG_PLAYGROUND_BLS_DEMO_UTIL_H
#define THRESHOLD_SIG_PLAYGROUND_BLS_DEMO_UTIL_H

#include <iostream>
#include <cstdlib>
#include <ctime>
#include <libBLS.h>
#include <array>
#include <openssl/sha.h>

using namespace std;

void sha256(uint8_t* out, string str);

/**
 * Implements a board member
 * Each board member has ha private/public key pair for BLS signatures
 */
class BoardMember  {
protected:
    string name;
    size_t memberId;
    shared_ptr<BLSPrivateKeyShare> skey;
    shared_ptr<BLSPublicKeyShare> pkey;
public:
    BoardMember(string name, size_t memberId, shared_ptr<BLSPrivateKeyShare> skey, size_t required, size_t tot)
            :  name(name), memberId(memberId), skey(skey), pkey(make_shared<BLSPublicKeyShare>(*skey->getPrivateKey(), tot, required)) {}
    shared_ptr<BLSSigShare> sign_message(string str);
    string get_name() {
        return name;
    }
    shared_ptr<string> get_sk_str() {
        return skey->toString();
    }
    shared_ptr<vector<string>> get_pk_str() {
        return pkey->toString();
    }
};

/**
 * Implements a verifier that confirms valid payments if signed by a threshold of board members
 */
class Verifier  {
protected:
    string name;
    shared_ptr<BLSPublicKey> pubkey;;
public:
    Verifier(string name, shared_ptr<BLSPublicKey> pubkey) : name(name), pubkey(pubkey) {}
    bool verify_message(string str, shared_ptr<BLSSignature> signature, size_t num_signed);
    string get_name() {
        return name;
    }
};

#endif //THRESHOLD_SIG_PLAYGROUND_BLS_DEMO_UTIL_H
