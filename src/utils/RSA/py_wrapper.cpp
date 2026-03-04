#include <pybind11/pybind11.h>
#include <gmpxx.h>
#include "RSA.h"
#include "MillerRabenTest.h"

namespace py = pybind11;

mpz_class pyint_to_mpz(const py::int_& pi){
    py::str hex_str = py::module::import("builtins").attr("hex")(pi);
    std::string str = hex_str;
    if(str.substr(0,2) == "0x"){
        str = str.substr(2);
    }

    return mpz_class(str,16);
}

py::int_ mpz_to_pyint(const mpz_class& mpz) {
    std::string hex_str = mpz.get_str(16);
    return py::int_(py::module::import("builtins").attr("int")(hex_str, 16));
}


class RSAKey{
private: 
    mpz_class first;
    mpz_class second;

public:
    RSAKey(const mpz_class& f, const mpz_class& s) : first(f), second(s){};

    RSAKey(const py::int_& f, const py::int_& s) 
        : first(pyint_to_mpz(f)), second(pyint_to_mpz(s)) {};

    py::int_ get_first() const{
        return mpz_to_pyint(first);
    }

    py::int_ get_second() const{
        return mpz_to_pyint(second);
    }

    const mpz_class& get_first_mpz() const { return first; }
    const mpz_class& get_second_mpz() const { return second; }
};


class PyRSA{
private:
    RSA rsa;
    bool keys_generated = false;

public:
    PyRSA() = default;

    void generate_keys(int key_size = 1024){
        rsa.generateKeys(key_size);
        keys_generated = true;
    }

    RSAKey get_public_key(){
        if(!keys_generated) throw std::runtime_error("Keys not generated");
        return RSAKey(rsa.public_key.first, rsa.public_key.second);
    }

    RSAKey get_private_key(){
        if(!keys_generated) throw std::runtime_error("Keys not generated");
        return RSAKey(rsa.private_key.first, rsa.private_key.second);
    }

    py::int_ encrypt(py::int_ data){
        if(!keys_generated) throw std::runtime_error("Keys not generated");
        
        mpz_class key_mpz = pyint_to_mpz(data);
        mpz_class encrypted = rsa.encryptKey(key_mpz);
        return mpz_to_pyint(encrypted);
    }

    py::int_ decrypt(py::int_ encrypted_key){
        if(!keys_generated) throw std::runtime_error("Keys not generated");
        
        mpz_class enc_mpz = pyint_to_mpz(encrypted_key);
        mpz_class decrypted = rsa.decryptKey(enc_mpz);
        return mpz_to_pyint(decrypted);
    }

    py::bytes encrypt_bytes(py::bytes bytes){
        if(!keys_generated) throw std::runtime_error("Keys not generated");

        std::string bytes_str = bytes;
        std::vector<unsigned char> bytes_vec(bytes_str.begin(), bytes_str.end());

        mpz_class key_mpz = rsa.bytesToMpz(bytes_vec);
        mpz_class encrypted = rsa.encryptKey(key_mpz);

        std::vector<unsigned char> encrypted_bytes = rsa.mpzToBytes(encrypted);
        return py::bytes(reinterpret_cast<char*>(encrypted_bytes.data()), encrypted_bytes.size());
    }

    py::bytes decrypt_bytes(py::bytes bytes){
        if(!keys_generated) throw std::runtime_error("Keys not generated");
        
        std::string bytes_str = bytes;
        std::vector<unsigned char> bytes_vec(bytes_str.begin(), bytes_str.end());
        
        mpz_class enc_mpz = rsa.bytesToMpz(bytes_vec);
        
        mpz_class decrypted = rsa.decryptKey(enc_mpz);
        
        std::vector<unsigned char> dec_bytes = rsa.mpzToBytes(decrypted);
        return py::bytes(reinterpret_cast<char*>(dec_bytes.data()), dec_bytes.size());
    }

    static py::int_ encrypt_with_key(py::int_ data, const RSAKey& key) {
        mpz_class data_mpz = pyint_to_mpz(data);
        
        RSA temp_rsa;
        temp_rsa.public_key = {key.get_first_mpz(), key.get_second_mpz()};
        
        mpz_class encrypted = temp_rsa.encryptKey(data_mpz);
        return mpz_to_pyint(encrypted);
    }
    
    static py::int_ decrypt_with_key(py::int_ encrypted_data, const RSAKey& key) {
        mpz_class enc_mpz = pyint_to_mpz(encrypted_data);
        
        RSA temp_rsa;
        temp_rsa.private_key = {key.get_first_mpz(), key.get_second_mpz()};
        temp_rsa.public_key = {0, key.get_second_mpz()}; 
        
        mpz_class decrypted = temp_rsa.decryptKey(enc_mpz);
        return mpz_to_pyint(decrypted);
    }
    
    static py::bytes encrypt_bytes_with_key(py::bytes bytes, const RSAKey& key) {
        std::string bytes_str = bytes;
        std::vector<unsigned char> bytes_vec(bytes_str.begin(), bytes_str.end());
        
        RSA temp_rsa;
        temp_rsa.public_key = {key.get_first_mpz(), key.get_second_mpz()};
        
        mpz_class data_mpz = temp_rsa.bytesToMpz(bytes_vec);
        
        if (data_mpz >= key.get_second_mpz()) {
            throw std::runtime_error("Data too large for RSA modulus");
        }
        
        mpz_class encrypted = temp_rsa.encryptKey(data_mpz);
        
        std::vector<unsigned char> encrypted_bytes = temp_rsa.mpzToBytes(encrypted);
        return py::bytes(reinterpret_cast<char*>(encrypted_bytes.data()), encrypted_bytes.size());
    }
    
    static py::bytes decrypt_bytes_with_key(py::bytes bytes, const RSAKey& key, size_t original_size = 0) {
        std::string bytes_str = bytes;
        std::vector<unsigned char> bytes_vec(bytes_str.begin(), bytes_str.end());
        
        RSA temp_rsa;
        temp_rsa.private_key = {key.get_first_mpz(), key.get_second_mpz()};
        temp_rsa.public_key = {0, key.get_second_mpz()}; 
        
        mpz_class enc_mpz = temp_rsa.bytesToMpz(bytes_vec);
        mpz_class decrypted = temp_rsa.decryptKey(enc_mpz);
        
        std::vector<unsigned char> dec_bytes = temp_rsa.mpzToBytes(decrypted);

        if (original_size > 0 && dec_bytes.size() < original_size) {
            dec_bytes.insert(dec_bytes.begin(), original_size - dec_bytes.size(), 0);
        }

        return py::bytes(reinterpret_cast<char*>(dec_bytes.data()), dec_bytes.size());
    }

};


PYBIND11_MODULE(rsa_core, m){
    m.doc() = "RSA core module";

    py::class_<RSAKey>(m, "RSAKey")
        .def(py::init<const py::int_&, const py::int_&>())
        .def_property_readonly("first", &RSAKey::get_first)
        .def_property_readonly("second", &RSAKey::get_second)
        .def("__repr__", [](const RSAKey& k){
            return "<RSAKey>";
        });

    py::class_<PyRSA>(m, "RSA")
        .def(py::init<>())
        .def("generate_keys", &PyRSA::generate_keys, py::arg("key_size") = 1024)
        .def_property_readonly("public_key", &PyRSA::get_public_key)
        .def_property_readonly("private_key", &PyRSA::get_private_key)

        .def("encrypt", &PyRSA::encrypt,
             "Encrypt (as integer)")
        .def("decrypt", &PyRSA::decrypt,
             "Decrypt (as integer)")
        
        .def("encrypt_bytes", &PyRSA::encrypt_bytes,
             "Encrypt (as bytes)")
        .def("decrypt_bytes", &PyRSA::decrypt_bytes,
             "Decrypt (as bytes)")
        .def_static("encrypt_with_key", &PyRSA::encrypt_with_key,
             py::arg("data"), py::arg("key"),
             "Encrypt key (as integer) with provided public key")
        .def_static("decrypt_with_key", &PyRSA::decrypt_with_key,
             py::arg("encrypted_data"), py::arg("key"),
             "Decrypt key (as integer) with provided private key")
        .def_static("encrypt_bytes_with_key", &PyRSA::encrypt_bytes_with_key,
             py::arg("data"), py::arg("key"),
             "Encrypt bytes with provided public key")
        .def_static("decrypt_bytes_with_key", &PyRSA::decrypt_bytes_with_key,
             py::arg("encrypted_data"), py::arg("key"),
             py::arg("original_size") = 0,
             "Decrypt bytes with provided private key");
};