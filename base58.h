// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Double-clicking selects the whole number as one word if it's all alphanumeric.
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H

#include <string>
#include <vector>

#include "bignum.h"
#include "key.h"
#include "allocators.h"

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const bool fTestNet=false;

template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

// Encode a byte sequence as a base58-encoded string
inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = CBigNum((unsigned int)58);
    CBigNum bn0 = CBigNum((unsigned int)0);

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += pszBase58[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

// Encode a byte vector as a base58-encoded string
inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

// Decode a base58-encoded string psz into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = (unsigned char)58;
    CBigNum bn = (unsigned char)0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(pszBase58, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setulong(p1 - pszBase58);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == pszBase58[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

// Decode a base58-encoded string psz that includes a checksum, into byte vector vchRet
// returns true if decoding is successful
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}





/** Base class for all base58-encoded data */
class CBase58Data
{
protected:
    // the version byte
    unsigned char nVersion;

    // the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

    CBase58Data()
    {
        nVersion = 0;
        vchData.clear();
    }

public:
    bool SetString(const char* psz)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty())
        {
            vchData.clear();
            nVersion = 0;
            return false;
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());
        OPENSSL_cleanse(&vchTemp[0], vchData.size());
        return true;
    }

    bool SetString(const std::string& str)
    {
        return SetString(str.c_str());
    }

};

/** base58-encoded Bitcoin addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CBitcoinAddress : public CBase58Data
{
public:
    enum
    {
        PUBKEY_ADDRESS = 30,
        SCRIPT_ADDRESS = 5,
        PUBKEY_ADDRESS_TEST = 111,
        SCRIPT_ADDRESS_TEST = 196,
    };

    bool IsValid() const
    {
        unsigned int nExpectedSize = 20;
        bool fExpectTestNet = false;
        switch(nVersion)
        {
            case PUBKEY_ADDRESS:
                nExpectedSize = 20; // Hash of public key
                fExpectTestNet = false;
                break;
            case SCRIPT_ADDRESS:
                nExpectedSize = 20; // Hash of CScript
                fExpectTestNet = false;
                break;

            case PUBKEY_ADDRESS_TEST:
                nExpectedSize = 20;
                fExpectTestNet = true;
                break;
            case SCRIPT_ADDRESS_TEST:
                nExpectedSize = 20;
                fExpectTestNet = true;
                break;

            default:
                return false;
        }
        return fExpectTestNet == fTestNet && vchData.size() == nExpectedSize;
    }

    CBitcoinAddress()
    {
    }

    CBitcoinAddress(const std::string& strAddress)
    {
        SetString(strAddress);
    }

    CBitcoinAddress(const char* pszAddress)
    {
        SetString(pszAddress);
    }

    bool GetKeyID(CKeyID &keyID) const {
        if (!IsValid())
            return false;
        switch (nVersion) {
        case PUBKEY_ADDRESS:
        case PUBKEY_ADDRESS_TEST: {
            uint160 id;
            memcpy(&id, &vchData[0], 20);
            keyID = CKeyID(id);
            return true;
        }
        default: return false;
        }
    }

};

#endif // BITCOIN_BASE58_H
