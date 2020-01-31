//
// Created by Lukas Burkhalter on 2020-01-31.
//

#include "bls-demo-util.h"

void sha256(uint8_t* out, string str) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(out, &sha256);
}


shared_ptr<BLSSigShare> BoardMember::sign_message(string str) {
    array<uint8_t, 32> hash_byte_arr;
    sha256(hash_byte_arr.data(), str);
    shared_ptr<array<uint8_t, 32>> hash_ptr = make_shared<array<uint8_t, 32> >(hash_byte_arr);
    return skey->sign(hash_ptr, memberId);
}


bool Verifier::verify_message(string str, shared_ptr<BLSSignature> signature, size_t num_signed) {
    array<uint8_t, 32> hash_byte_arr;
    sha256(hash_byte_arr.data(), str);
    shared_ptr<array<uint8_t, 32>> hash_ptr = make_shared<array<uint8_t, 32> >(hash_byte_arr);
    return pubkey->VerifySig(hash_ptr, signature, num_signed, pubkey->getTotalSigners());
}