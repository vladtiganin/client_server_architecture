#include <pybind11/pybind11.h>
#include <pybind11/pybind11.h>
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

    py::int_ get_first() const{
        return mpz_to_pyint(first);
    }

    py::int_ get_second() const{
        return mpz_to_pyint(second);
    }
};


class PyRSA{
private:
    RSA rsa;
    bool keys_generated = false;

public:
    PyRSA() = default;

    void generate_keys(){
        rsa.generateKeys();
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
};


PYBIND11_MODULE(rsa_core, m){
    m.doc() = "RSA core module";

    py::class_<RSAKey>(m, "RSAKey")
        .def_property_readonly("first", &RSAKey::get_first)
        .def_property_readonly("second", &RSAKey::get_second)
        .def("__repr__", [](const RSAKey& k){
            return "<RSAKey";
        });

    py::class_<PyRSA>(m, "RSA")
        .def(py::init<>())
        .def("generate_keys", &PyRSA::generate_keys)
        .def_property_readonly("public_key", &PyRSA::get_public_key)
        .def_property_readonly("private_key", &PyRSA::get_private_key);
}