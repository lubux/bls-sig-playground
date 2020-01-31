#include <iostream>
#include <cstdlib>
#include <ctime>
#include <libBLS.h>
#include <array>
#include <openssl/sha.h>
#include "bls-demo-util.h"

using namespace std;

int main() {
    srand((int) time(0));
    // number of board members
    size_t num_all = 5;
    // number of signatures required
    size_t num_signed = 3;
    // number of requests performed
    int num_requests = 50;


    vector<BoardMember *> boardMembers(num_all);

    // tursted setup of keys
    shared_ptr<pair<shared_ptr<vector<shared_ptr<BLSPrivateKeyShare>>>,
            shared_ptr<BLSPublicKey>>> keys = BLSPrivateKeyShare::generateSampleKeys(num_signed, num_all);
    shared_ptr<vector<shared_ptr<BLSPrivateKeyShare>>> Skeys = keys->first;
    shared_ptr<BLSPublicKey> pubkey = keys->second;

    // Verifier is in possession of the golbal public key
    Verifier ver = Verifier("Verifier", pubkey);

    // Create the board members and distribute them to the board members
    for (size_t i = 0; i < num_all; ++i) {
        boardMembers.at(i) = new BoardMember("Member " + to_string(i), i + 1, Skeys->at(i), num_signed, num_all);
        cout << boardMembers.at(i)->get_name() << " joins the company board" << endl;
        cout << "secret share: (DEBUG)" << *boardMembers.at(i)->get_sk_str().get() << endl;
    }

    // generate the payment requests
    vector<string> paymentRequests(num_requests);
    for (size_t i = 0; i < num_requests; ++i) {
        paymentRequests.at(i) = to_string(rand() % 1000) + "$";
    }

    // Simulation begins
    for (size_t j = 0; j < num_requests; ++j) {
        cout << "ID " << j << ": New Payment ->  " << paymentRequests.at(j) << endl;
        vector<shared_ptr<BLSSigShare>> received_signatures;

        for (size_t i = 0; i < num_all; ++i) {
            // With probability 0.5 the current board member signs the request
            if (rand() % 2 == 0) {
                cout << boardMembers.at(i)->get_name() << " signs the request" << endl;
                shared_ptr<BLSSigShare> sigShare = boardMembers.at(i)->sign_message(paymentRequests.at(j));
                received_signatures.push_back(sigShare);
            }
        }

        // if some board members have signed the request we can verify the aggregated signature
        if (received_signatures.size() > 0) {
            size_t min_req;
            if (received_signatures.size() < num_signed)
                min_req = received_signatures.size();
            else
                min_req = num_signed;
            // create the aggregated signature
            BLSSigShareSet sigSet(min_req, num_all);
            if (received_signatures.size() < num_signed)
                sigSet = BLSSigShareSet(received_signatures.size(), num_all);
            else
                sigSet = BLSSigShareSet(num_signed, num_all);
            for (size_t i = 0; i < received_signatures.size(); ++i)
                sigSet.addSigShare(received_signatures.at(i));
            shared_ptr<BLSSignature> common_sig_ptr = sigSet.merge();

            // the verifier checks if the payment is approved
            bool ok;
            try {
                ok = ver.verify_message(paymentRequests.at(j), common_sig_ptr, num_signed);
            } catch (signatures::Bls::IncorrectInput& e) {
                ok = false;
            }
            if (ok) {
                cout << "Verification is successfull :), Payment confirmed" << endl;
            } else {
                cout << "Verification failed :( " << endl;
            }
        }
    }

    return 0;
}