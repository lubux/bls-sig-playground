#include <iostream>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <ctime>
#include <libBLS.h>
#include <array>
#include <openssl/sha.h>
#include "bls-demo-util.h"

using namespace std;

int main() {
    srand((int) time(0));

    cout << "Please enter the number of board members:" << endl;
    // number of board members
    size_t num_all;
    cin >> num_all;
    cout << "How many signatures are required per approval?" << endl;
    // number of signatures required
    size_t num_signed = 3;
    cin >> num_signed;
    if (num_signed > num_all || num_signed < 0) {
        num_signed = num_all;
    }


    cout << "Company is being created with " << num_all << " board members, " << num_signed << " approvals are required for a valid payment request." << endl;
    cout << "Trusted key setup starts now..." << endl;

    vector<unique_ptr<BoardMember>> boardMembers(num_all);
    // tursted setup of keys
    shared_ptr<pair<shared_ptr<vector<shared_ptr<BLSPrivateKeyShare>>>,
            shared_ptr<BLSPublicKey>>> keys = BLSPrivateKeyShare::generateSampleKeys(num_signed, num_all);
    shared_ptr<vector<shared_ptr<BLSPrivateKeyShare>>> Skeys = keys->first;
    shared_ptr<BLSPublicKey> pubkey = keys->second;

    // Verifier is in possession of the golbal public key
    Verifier ver = Verifier("Verifier", pubkey);

    // Create the board members and distribute them to the board members
    for (size_t i = 0; i < num_all; ++i) {
        boardMembers.at(i) = make_unique<BoardMember>("Member " + to_string(i), i + 1, Skeys->at(i), num_signed, num_all);
        cout << boardMembers.at(i)->get_name() << " joins the company board" << endl;
        cout << "secret share: (DEBUG)" << *boardMembers.at(i)->get_sk_str() << endl;
    }

    cout << "######################################################################" << endl;
    while(1) {
        char x;
        cout << "Do you want to enter a new payment? (y/n)" << endl;
        cin >> x;
        if (x == 'n')
            break;

        int amount = 0;
        string reason;
        cout << "Enter a new payment" << endl;
        cout << "Amount in $ (e.g., 100):" << endl;
        cin >> amount;
        cout << "Reason (e.g., birthday cake):" << endl;
        cin >> reason;
        string payment = to_string(amount) + "$, " + reason;
        cout << "The payment has been created ->  \"" << payment << "\"" << endl;

        cout << "Member of the board asked for approval"<< endl;

        vector<shared_ptr<BLSSigShare>> received_signatures;
        int count = 0;
        for (size_t i = 0; i < num_all && count < num_signed; ++i) {
            // With probability 0.5 the current board member signs the request
            if (rand() % 2 == 0) {
                cout << boardMembers.at(i)->get_name() << " signs the request" << endl;
                shared_ptr<BLSSigShare> sigShare = boardMembers.at(i)->sign_message(payment);
                received_signatures.push_back(sigShare);
                count++;
            } else {
                cout << boardMembers.at(i)->get_name() << " declines the request" << endl;
            }
            this_thread::sleep_for(chrono::milliseconds(500));
        }

        cout << "Do you want to send the payment to the admin/verifier? " << num_signed << " signature are required. (y/n):" << endl;
        cin >> x;
        if (x == 'n' || received_signatures.size() <= 0) {
            cout << "The payment has not been approved" << endl;
            continue;
        }


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

        cout << "Sending the payment to the verifier with the signature..." << endl;

        // the verifier checks if the payment is approved
        bool ok;
        try {
            ok = ver.verify_message(payment, common_sig_ptr, num_signed);
        } catch (signatures::Bls::IncorrectInput& e) {
            ok = false;
        }
        if (ok) {
            cout << "||| The verifier approves the payment \"" <<  payment << "\" :D |||" << endl;
        } else {
            cout << "||| The verifier declines the payment the signature is INVALID! |||" << endl;
        }

        cout << "######################################################################" << endl;
    }
    cout << "DONE" << endl;
    return 0;
}