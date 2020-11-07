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

#define MAX_BID (1 << 2)
#define NORMALIZE_POWER 8
// ReEncrypt evevry REENCRYPT_ROUND iterations
#define REENCRYPT_ROUND 3
#define FIRST_ITERA_ROUNDS 0

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

    vector<int> galois_elts;
    auto n = params.poly_modulus_degree();
    if (logm > ceil(log2(n))){
        throw logic_error("m > n is not allowed.");
    }
    for (int i = 0; i < ceil(log2(n)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }

    vector<Ciphertext> result(1 << logm);
    for (int i = 0; i < result.size(); i++){
        result[i] = encrypted;
    }
    Ciphertext tempctxt;
    Ciphertext tempctxt_rotated;
    Ciphertext tempctxt_shifted;
    Ciphertext tempctxt_rotatedshifted;

    for (uint32_t i = 0; i < logm; i++) {
        int num_ops =  1 << i;


        int index_raw = (n << 1) - (1 << i);
        int index = (index_raw * galois_elts[i]) % (n << 1);

        for (uint32_t a = 0; a < num_ops; a++) {
            evaluator->apply_galois(result[a], galois_elts[i], galkey, tempctxt_rotated);

            // tempctxt_shifted, c1
            // c1 = c0*x^index_raw
            multiply_power_of_X(result[a], tempctxt_shifted, index_raw, params);

            // c[k] = c[k] + sub(c[k], N/2^i + 1)
            evaluator->add_inplace(result[a], tempctxt_rotated);

            evaluator->apply_galois(tempctxt_shifted, galois_elts[i], galkey, tempctxt_rotatedshifted);
            //cout << i << " " << logm - 1 << " " << a << " multiply 2" << endl;

            multiply_power_of_X(tempctxt_rotated, tempctxt_rotatedshifted, index, params);

            // c[k + 2^i] = c'[k] + sub(c'[k], N/2^i+1)
            evaluator->add(tempctxt_shifted, tempctxt_rotatedshifted, result[a + num_ops]);
        }
    }
    vector<Ciphertext>::const_iterator first = result.begin();
    vector<Ciphertext>::const_iterator last = result.begin() + m;
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
    cout << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    //parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 30, 30, 60 }));
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    //parms.set_plain_modulus(1073741824);
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 30));

    cout << "plain modulus: " << parms.plain_modulus().value() << endl;

    context = SEALContext::Create(parms);
    KeyGenerator keygen(context);
    PublicKey public_key_val = keygen.public_key();
    public_key = &public_key_val;
    SecretKey secret_key_val = keygen.secret_key();
    secret_key = &secret_key_val;
    RelinKeys relin_keys_val = keygen.relin_keys_local();
    relin_keys = &relin_keys_val;
    Encryptor encryptor_val(context, public_key_val);
    encryptor = &encryptor_val;
    Evaluator evaluatorval(context);
    evaluator = &evaluatorval;
    Decryptor decryptor_val(context, secret_key_val);
    decryptor = &decryptor_val;
    IntegerEncoder encoder(context);

    vector<uint32_t> galois_elts;
    //vector<uint64_t> galois_elts;

    int N = parms.poly_modulus_degree();
    int logN = get_power_of_two(N);

    //cout << "printing galois elements...";
    for (int i = 0; i < logN; i++) {
        galois_elts.push_back((N + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }

    GaloisKeys gal_keys = keygen.galois_keys_local(galois_elts);

    srand(time(0));
    auto coeff_mod_count = parms.coeff_modulus().size();
    cout << coeff_mod_count << endl;

    cout << parms.coeff_modulus()[0].value() << endl;

    for (int j = 0; j < 2; j++) {
        cout << "\nrun for " << j+1 << " time\n";
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
    return 0;
}
