#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "assert.h"
#include "random"

#include "seal/util/polyarithsmallmod.h"
#include "unistd.h"

using namespace std;
using namespace seal;
using namespace seal::util;

std::shared_ptr<SEALContext> context;
Encryptor* encryptor;
Evaluator* evaluator;
Decryptor* decryptor;
PublicKey* public_key;
SecretKey* secret_key;
RelinKeys* relin_keys;

void multiply_power_of_X(const Ciphertext &encrypted, Ciphertext &destination,
                                    uint32_t index, EncryptionParameters& params) {

    auto coeff_mod_count = params.coeff_modulus().size();
    auto coeff_count = params.poly_modulus_degree();
    auto encrypted_count = encrypted.size();

    //cout << "coeff mod count for power of X = " << coeff_mod_count << endl; 
    //cout << "coeff count for power of X = " << coeff_count << endl; 

    // First copy over.
    destination = encrypted;

    // Prepare for destination
    // Multiply X^index for each ciphertext polynomial
    for (int i = 0; i < encrypted_count; i++) {
        for (int j = 0; j < coeff_mod_count; j++) {
            seal::util::negacyclic_shift_poly_coeffmod(
                encrypted.data(i) + (j * coeff_count), coeff_count, index,
                params.coeff_modulus()[j],
                destination.data(i) + (j * coeff_count));
        }
    }
}

vector<Ciphertext> expand_query(const Ciphertext &encrypted, uint32_t m, EncryptionParameters& params, GaloisKeys& galkey) {

    // Assume that m is a power of 2. If not, round it to the next power of 2.
    uint32_t logm = ceil(log2(m));
    Plaintext two("2");

    vector<int> galois_elts;
    auto n = params.poly_modulus_degree();
    if (logm > ceil(log2(n))){
        throw logic_error("m > n is not allowed."); 
    }
    for (int i = 0; i < ceil(log2(n)); i++) {
        galois_elts.push_back((n + exponentiate_uint64(2, i)) / exponentiate_uint64(2, i));
    }

    vector<Ciphertext> temp;
    temp.push_back(encrypted);
    Ciphertext tempctxt;
    Ciphertext tempctxt_rotated;
    Ciphertext tempctxt_shifted;
    Ciphertext tempctxt_rotatedshifted;


    for (uint32_t i = 0; i < logm - 1; i++) {
        vector<Ciphertext> newtemp(temp.size() << 1);
        // temp[a] = (j0 = a (mod 2**i) ? ) : Enc(x^{j0 - a}) else Enc(0).  With
        // some scaling....
        int index_raw = (n << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (n << 1);

        //cout << i << " " << logm - 1 << endl;
        assert(temp.size() == pow(2, i));
        for (uint32_t a = 0; a < temp.size(); a++) {
            evaluator->apply_galois(temp[a], galois_elts[i], galkey, tempctxt_rotated);

            // c0 + sub(c0, N/2^j + 1)
            evaluator->add(temp[a], tempctxt_rotated, newtemp[a]);

            // tempctxt_shifted, c1
            // c1 = c0*x^index_raw
            multiply_power_of_X(temp[a], tempctxt_shifted, index_raw, params);

            multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index, params);

            // Enc(2^i x^j) if j = 0 (mod 2**i).
            evaluator->add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]);
        }
        temp = newtemp;
    }
    // Last step of the loop
    vector<Ciphertext> newtemp(temp.size() << 1);
    int index_raw = (n << 1) - (1 << (logm - 1));
    int index = (index_raw * galois_elts[logm - 1]) % (n << 1);
    for (uint32_t a = 0; a < temp.size(); a++) {
        if (a >= (m - (1 << (logm - 1)))) {                       // corner case.
            evaluator->multiply_plain(temp[a], two, newtemp[a]); // plain multiplication by 2.
        }
        else {
            evaluator->apply_galois(temp[a], galois_elts[logm - 1], galkey, tempctxt_rotated);

            evaluator->add(temp[a], tempctxt_rotated, newtemp[a]);

            multiply_power_of_X(temp[a], tempctxt_shifted, index_raw, params);

            multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index, params);

            evaluator->add(tempctxt_shifted, tempctxt_rotatedshifted, newtemp[a + temp.size()]);
        }
    }

    vector<Ciphertext>::const_iterator first = newtemp.begin();
    vector<Ciphertext>::const_iterator last = newtemp.begin() + m;
    assert(newtemp.size() == m);
    vector<Ciphertext> newVec(first, last);
    return newVec;
}

bool uniTest(vector<uint32_t>& galois_elts, GaloisKeys& gal_keys, int N, EncryptionParameters& parms, IntegerEncoder& encoder) {
    Ciphertext one;
    int degree = rand() % 8192;
    int coefficient = rand() % 100000 + 1;
    cout << "coefficient: " << coefficient << " degree: " << degree << endl;
    stringstream ss;
    ss << std::hex << coefficient;
    ss << "x^" << std::dec << degree;
    string poly = ss.str();
    cout << poly << endl;
    Plaintext plain_val(poly);
    encryptor->encrypt(plain_val, one);
    vector<Ciphertext> expanded_vec = expand_query(one, N, parms, gal_keys);

    bool res = true;
    for (int i = 0; i < expanded_vec.size(); i++) {
        Plaintext res_decrypted1;
        decryptor->decrypt(expanded_vec[i], res_decrypted1);
        if (encoder.decode_int64(res_decrypted1) != 0) {
            if (i != degree || encoder.decode_int64(res_decrypted1) != coefficient * N) {
                res = false;
            }
            cout << i << " " << encoder.decode_int64(res_decrypted1) << endl;
        }
    }
    cout << res << endl;
    return res;
}

int main(int argc, char *argv[]) {
    size_t poly_modulus_degree = 8192;

    cout << "poly modulus degree: " << poly_modulus_degree << endl;

    EncryptionParameters parms(scheme_type::BFV);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(DefaultParams::coeff_modulus_128(8192));
    //parms.set_plain_modulus(1073741824);
    parms.set_plain_modulus(1073741824); // 2^30

    cout << "plain modulus: " << parms.plain_modulus().value() << endl;

    context = SEALContext::Create(parms);
    KeyGenerator keygen(context);
    PublicKey public_key_val = keygen.public_key();
    public_key = &public_key_val;
    SecretKey secret_key_val = keygen.secret_key();
    secret_key = &secret_key_val;
    //RelinKeys relin_keys_val = keygen.relin_keys_local();
    //relin_keys = &relin_keys_val;
    Encryptor encryptor_val(context, public_key_val);
    encryptor = &encryptor_val;
    Evaluator evaluatorval(context);
    evaluator = &evaluatorval;
    Decryptor decryptor_val(context, secret_key_val);
    decryptor = &decryptor_val;
    IntegerEncoder encoder(context);

    vector<uint64_t> galois_elts;
    int N = parms.poly_modulus_degree();
    int logN = get_power_of_two(N);

    for (int i = 0; i < logN; i++) {
        galois_elts.push_back((N + exponentiate_uint64(2, i)) / exponentiate_uint64(2, i));
    }

    GaloisKeys gal_keys = keygen.galois_keys(6, galois_elts);

    srand(time(0));

    for (int j = 0; j < 2; j++) {
        Ciphertext encrypted;
        Plaintext plain_val("Ax^1");
        encryptor->encrypt(plain_val, encrypted);

        vector<Ciphertext> expanded_vec = expand_query(encrypted, 4, parms, gal_keys);
        
        for (int i = 0; i < expanded_vec.size(); i++) {
            Plaintext res_decrypted1;
            decryptor->decrypt(expanded_vec[i], res_decrypted1);
            cout << i << " " << encoder.decode_int64(res_decrypted1) << endl;
        }
    }

    /*
    int test_times = 50;
    if (argc >= 2) {
        test_times = atoi(argv[1]);
    }
    int failed_cases = 0;
    for (int i = 0; i < test_times; i++) {
        if (uniTest(galois_elts, gal_keys, N, parms, encoder) != true) {
            failed_cases++;
        }
    }
    cout << "failed cases: " << failed_cases << endl;
    */
    return 0;
}