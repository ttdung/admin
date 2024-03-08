/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file  zx509.h
///
/// \brief X.509 certificate handling functionality
///
/// \author Alan Dunn and J. Ayo Akinyele
///

#ifndef __ZX509__
#define __ZX509__

#include <memory>
#include <string>
#include <utility>
#include <vector>

/* All this functionality assumes the OpenSSL library has already been
   initialized */
#define SERIAL_BITS        128
#define DAYS               30
#define CRL_UPDATE_SCHED   DAYS*24*60*60

namespace oabe {

class KeyCertifier;
class DistinguishedName {
public:
    DistinguishedName();
    ~DistinguishedName();

    static void makeDistinguishedName(
        DistinguishedName& dn,
        const std::vector<std::pair<std::string, std::string>>& rdnPairs);

private:
    class Impl;
    std::unique_ptr<Impl> ptr_;

    friend class KeyCertifier;
};

/*! \brief Generate X509 certificates for public signature keys
 */
class KeyCertifier {
public:
    /*! \brief Create a certifier from a private key
     *
     * @param[out] certifier The resultant key certifier
     * @param[in] privateKey A private key previously generated by a
     *                       zeutro::crypto::SignatureKeypairGenerator
     * @throws zeutro::crypto::CryptoException if key is misformatted
     */
    static void fromKeyString(KeyCertifier& certifier,
                              const std::string& privateKey);

    // Note: 1461 days = 4 * 365 days + 1 day for a leap year.  This
    // makes the default validity a fixed number of years without
    // having to figure out the right number of days based on the
    // current year.

    /*! \brief Generate a signed certificate for a public key
     *
     * @param[out] cert A PEM-encoded X509 certificate certifying
     *                  publicKey
     * @param[in] publicKey A public key previously generated by a
     *                      zeutro::crypto::SignatureKeypairGenerator
     * @param[in] commonName A common name to use in the subject in
     *                       the resultant X509 certificate (i.e. for
     *                       identifying the different certificates)
     * @param[in] daysValid The number of days from the current time
     *                      at which the certificate should be set to
     *                      expire
     */
    void generateCertificate(std::string& cert,
                             const std::string& publicKey,
                             const std::string& commonName,
                             int daysValid=1461);

    /*! \brief Generate a signed certificate for a public key
     *
     * @param[out] cert A PEM-encoded X509 certificate certifying
     *                  publicKey
     * @param[in] publicKey A public key previously generated by a
     *                      zeutro::crypto::SignatureKeypairGenerator
     * @param[in] issuerDn The distinguished name of the certificate
     *                     issuer
     * @param[in] subjectDn The distinguished name of the certificate
     *                      subject
     * @param[in] daysValid The number of days from the current time
     *                      at which the certificate should be set to
     *                      expire
     */
    void generateCertificate(std::string& cert,
                             const std::string& publicKey,
                             const DistinguishedName& issuerDn,
                             const DistinguishedName& subjectDn,
                             int daysValid=1461);

    ~KeyCertifier();

protected:
    EVP_PKEY* privateKey_;

    static bool addDnToX509Name(const DistinguishedName& dn,
                                X509_NAME* name);
};

/*! \brief Generate self-signed CA certificate that serves as signer
 *         for all certificates generated from KeyCertifiers
 *
 * @param[out] cert A PEM-encoded X509 certificate certifying the
 *                  public portion of privateKey
 * @param[in] privateKey A private key previously generated by a
 *                       zeutro::crypto::SignatureKeypairGenerator
 * @param[in] daysValid The number of days from the current time
 *                      at which the certificate should be set to
 *                      expire
 */
void certifyKeyAsCA(std::string& cert,
                    const std::string& privateKey,
                    int daysValid=1461);

/*! \brief Get the first common name in the subject out of a
 *         certificate
 *
 * @param[out] commonName set to common name as a UTF-8 string
 * @return 1 if OK and common name returned, 0 if no common name, -1 on error
 */
int getFirstSubjectCommonName(std::string &commonName, X509* cert);

/*! \brief Get the serial number of a certificate
 *
 * @param[out] serialNumber set to the serial number as a byte string
 * @return 1 if OK and serial number returned, 0 if no serial number, -1 on error
 */
int getSerialNumber(OpenABEByteString& serial, X509* cert);

/*! \brief Generate X509 certificate revocation list management
 */
class CertRevList {
public:
    CertRevList(const std::string& crl_path);
    ~CertRevList();

    void setStartCrlNumber(int crlNumber) {
        crlNumber_ = crlNumber;
    }

    void createNewCrl(const std::string& ca_cert, const std::string& ca_privKey);
    bool loadCrlFile();
    bool revokeCertificate(const std::string& client_cert);

    bool isRevoked(const std::string& client_cert);
    bool isRevoked(X509 *cert);
    bool loadRevokedList();

private:
    std::string crl_path_;
    X509_CRL* crl_;
    long int crlNumber_;

    void writeCrlFile();
    std::vector<std::string> revList_;
    bool revListSet_;
};

}

#endif
