#include "Thread.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include "util.h"
#include "key.h"
#include "base58.h"
using namespace std;

const string strMessageMagic = "MPPT:\n";

static const string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
	string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--) {
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for(i = 0; (i <4) ; i++)
				ret += base64_chars[char_array_4[i]];
			i = 0;
		}
	}

	if (i)
	{
		for(j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++)
			ret += base64_chars[char_array_4[j]];

		while((i++ < 3)) ret += '=';
	}

	return ret;

}

Thread::Thread(Server *s) {
	server=s;
	fd=0;
}

Thread::~Thread()
{

}

int ECDSA_SIG_recover_key_GFp2(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
	if (!eckey) return 0;

	int ret = 0;
	BN_CTX *ctx = NULL;

	BIGNUM *x = NULL;
	BIGNUM *e = NULL;
	BIGNUM *order = NULL;
	BIGNUM *sor = NULL;
	BIGNUM *eor = NULL;
	BIGNUM *field = NULL;
	EC_POINT *R = NULL;
	EC_POINT *O = NULL;
	EC_POINT *Q = NULL;
	BIGNUM *rr = NULL;
	BIGNUM *zero = NULL;
	int n = 0;
	int i = recid / 2;

	const EC_GROUP *group = EC_KEY_get0_group(eckey);
	if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);
	if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
	x = BN_CTX_get(ctx);
	if (!BN_copy(x, order)) { ret=-1; goto err; }
	if (!BN_mul_word(x, i)) { ret=-1; goto err; }
	if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
	field = BN_CTX_get(ctx);
	if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
	if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
	if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
	if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
	if (check)
	{
		if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
		if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
		if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
	}
	if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
	n = EC_GROUP_get_degree(group);
	e = BN_CTX_get(ctx);
	if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
	if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
	zero = BN_CTX_get(ctx);
	if (!BN_zero(zero)) { ret=-1; goto err; }
	if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
	rr = BN_CTX_get(ctx);
	if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
	sor = BN_CTX_get(ctx);
	if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
	eor = BN_CTX_get(ctx);
	if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
	if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
	if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

	ret = 1;

	err:
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (R != NULL) EC_POINT_free(R);
	if (O != NULL) EC_POINT_free(O);
	if (Q != NULL) EC_POINT_free(Q);
	return ret;
}

bool SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig,EC_KEY* pkey)
{
	if (vchSig.size() != 65)
		return false;
	int nV = vchSig[0];
	if (nV<27 || nV>=35)
		return false;
	ECDSA_SIG *sig = ECDSA_SIG_new();
	BN_bin2bn(&vchSig[1],32,sig->r);
	BN_bin2bn(&vchSig[33],32,sig->s);

	EC_KEY_free(pkey);
	pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (nV >= 31)
	{
		bool fCompressed=false;
		EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
		nV -= 4;
	}
	if (ECDSA_SIG_recover_key_GFp2(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
	{
		ECDSA_SIG_free(sig);
		return true;
	}
	return false;
}

CPubKey GetPubKey(EC_KEY* pkey)
{
	int nSize = i2o_ECPublicKey(pkey, NULL);
	std::vector<unsigned char> vchPubKey(nSize, 0);
	unsigned char* pbegin = &vchPubKey[0];
	if (i2o_ECPublicKey(pkey, &pbegin) != nSize)
	{
		//error
	}
	return CPubKey(vchPubKey);
}

bool verifysign(string& strAddress,string& strSign,string& strMessage)
{
	SHA256_CTX ctx;
	uint256 hash1,hash2;
	const string strMessageMagic = "MPPT:\n";
	EC_KEY* pkey=EC_KEY_new_by_curve_name(NID_secp256k1);;

	CBitcoinAddress addr(strAddress);
	if (!addr.IsValid()) {
		fprintf(stderr, "Invalid address\n");
		return(false);
	}

	CKeyID keyID;
	if (!addr.GetKeyID(keyID)) {
		fprintf(stderr, "Address does not refer to key\n");
		return(false);
	}

	bool fInvalid = false;
	vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

	if (fInvalid) {
		fprintf(stderr, "Malformed base64 encoding\n");
		return(false);
	}

	//CKey key;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx,strMessageMagic.c_str(),strMessageMagic.size());
	SHA256_Update(&ctx,strMessage.c_str(),strMessage.size());
	SHA256_Final((unsigned char *)&hash1,&ctx);
	SHA256((unsigned char *)&hash1,sizeof(hash1),(unsigned char *)&hash2);

	if (!SetCompactSignature(hash2, vchSig,pkey)) {
		fprintf(stderr, "Error reading signature\n");
		return(false);
	}

	// 0 is "success" in standard UNIX return codes
	if (GetPubKey(pkey).GetID() == keyID) {
		//printf("pass\n");
		return(true);
	} else {
		//printf("fail\n");
		return(false);
	}
}

bool checkMppt(string msg)
{
	string address="DCxfLwhHcWQ97Vx6fmjwfNLeukEKWxN8Fp",production,signature;
	int kr;

	kr=msg.find("|");
	if (kr<=0) return(false);
	production=msg.substr(0,kr);
	signature=msg.substr(kr+1,msg.size());
	return(verifysign(address,signature,production));
}

void generate(string& adres,string& privkey)
{
	uint160 a;
	CKey key;
	unsigned char *aa;
	bool comp;

	key.MakeNewKey(false);
	a=key.GetPubKey().GetID();
	aa=(unsigned char *)&a;
	std::vector<unsigned char> vch;
	vch.push_back(CBitcoinAddress::PUBKEY_ADDRESS);
	vch.insert(vch.end(), aa, aa+20);
	adres=EncodeBase58Check(vch);
	privkey=base64_encode(&key.GetSecret(comp)[0],key.GetSecret(comp).size());
}

void Thread::start()
{
	CKey key;
	vector<unsigned char> v,vsig;
	bool bb;
	string tocomp,signature,msg;
	SHA256_CTX ctx;
	uint256 hash1,hash2;
	char buf[MAXBUF];
	int n;

	//string address,privkey;
	//generate(address,privkey);
	//printf("%s %s",address.c_str(),privkey.c_str());
	v=DecodeBase64("3G7tsmh5khO3M9430cFYGIAyj3CD5ODRYJlV79h2MDg=",&bb);
	if (bb)
	{
		fprintf(stderr,"invalid secret\n");
		return;
	}
	n=read(fd,buf,MAXBUF);
	if (n>0)
	{
		buf[n]=0;
		std::stringstream ss;
		ss << fixed << setprecision(2) << (rand()%1000)/10.0;
		tocomp=ss.str()+" "+buf;
		key.SetSecret(v);
		SHA256_Init(&ctx);
		SHA256_Update(&ctx,strMessageMagic.c_str(),strMessageMagic.size());
		SHA256_Update(&ctx,tocomp.c_str(),tocomp.size());
		SHA256_Final((unsigned char *)&hash1,&ctx);
		SHA256((unsigned char *)&hash1,sizeof(hash1),(unsigned char *)&hash2);
		if (!key.SignCompact(hash2, vsig)) {
			printf("Sign failed\n");
		}
		signature=base64_encode(&vsig[0],vsig.size());
		msg=tocomp+"|"+signature;
		write(fd,msg.c_str(),msg.size());
		printf("%s\n",msg.c_str());
		printf("%d\n",checkMppt(msg));
	}
	close(fd);
}
