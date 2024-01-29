#include <libcryptosec/MessageDigest.h>

MessageDigest::MessageDigest()
{
	this->ctx = EVP_MD_CTX_new();
	this->state = MessageDigest::NO_INIT;
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm)
		throw (MessageDigestException)
{
	int rc;
	const EVP_MD *md;
	this->state = MessageDigest::INIT;
	this->algorithm = algorithm;
	this->ctx = EVP_MD_CTX_new();
	md = MessageDigest::getMessageDigest(this->algorithm);
	EVP_MD_CTX_init(this->ctx);
	rc = EVP_DigestInit(this->ctx, md);
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::MessageDigest");
	}
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm, Engine &engine)
		throw (MessageDigestException)
{
	int rc;
	const EVP_MD *md;
	this->state = MessageDigest::INIT;
	this->algorithm = algorithm;
	this->ctx = EVP_MD_CTX_new();
	md = MessageDigest::getMessageDigest(this->algorithm);
	EVP_MD_CTX_init(this->ctx);
	rc = EVP_DigestInit_ex(this->ctx, md, engine.getEngine());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::MessageDigest");
	}
}

MessageDigest::~MessageDigest()
{
	EVP_MD_CTX_free(this->ctx);
}

void MessageDigest::init(MessageDigest::Algorithm algorithm)
		throw (MessageDigestException)
{
	int rc;
	const EVP_MD *md;
	if (this->state != MessageDigest::NO_INIT){
		EVP_MD_CTX_reset(this->ctx); //martin: EVP_MD_CTX_cleanup -> EVP_MD_CTX_reset see openssl1.1.c/CHANGES:647
	}
	this->algorithm = algorithm;
	md = MessageDigest::getMessageDigest(this->algorithm);
	rc = EVP_DigestInit(this->ctx, md);
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::init");
	}
	this->state = MessageDigest::INIT;
}

void MessageDigest::init(MessageDigest::Algorithm algorithm, Engine &engine)
		throw (MessageDigestException)
{
	int rc;
	const EVP_MD *md;
	if (this->state != MessageDigest::NO_INIT){
		EVP_MD_CTX_reset(this->ctx); //martin: EVP_MD_CTX_cleanup -> EVP_MD_CTX_reset see openssl1.1.c/CHANGES:647
	}
	this->algorithm = algorithm;
	md = MessageDigest::getMessageDigest(this->algorithm);
	EVP_MD_CTX_init(this->ctx);
	rc = EVP_DigestInit_ex(this->ctx, md, engine.getEngine());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::init");
	}
	this->state = MessageDigest::INIT;
}

void MessageDigest::update(ByteArray &data) throw (MessageDigestException, InvalidStateException)
{
	int rc;
	if (this->state == MessageDigest::NO_INIT)
	{
		throw InvalidStateException("MessageDigest::update");
	}
	rc = EVP_DigestUpdate(this->ctx, data.getDataPointer(), data.size());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_UPDATE, "MessageDigest::update");
	}
	this->state = MessageDigest::UPDATE;
}

void MessageDigest::update(std::string &data) throw (MessageDigestException, InvalidStateException)
{
	ByteArray content(data);
	this->update(content);
}

ByteArray MessageDigest::doFinal() throw (MessageDigestException, InvalidStateException)
{
	unsigned char *digest;
	unsigned int ndigest;
	int rc;
	if (this->state == MessageDigest::NO_INIT || this->state == MessageDigest::INIT)
	{
		throw InvalidStateException("MessageDigest::doFinal");
	}
	digest = (unsigned char *)calloc(EVP_MAX_MD_SIZE + 1, sizeof(unsigned char));
	rc = EVP_DigestFinal_ex(this->ctx, digest, &ndigest);
	EVP_MD_CTX_reset(this->ctx); //martin: EVP_MD_CTX_cleanup -> EVP_MD_CTX_reset see openssl1.1.c/CHANGES:647
	this->state = MessageDigest::NO_INIT;
	if (!rc)
	{
		free(digest);
		throw MessageDigestException(MessageDigestException::CTX_FINISH, "MessageDigest::doFinal");
	}
	ByteArray ret(digest, ndigest);
	free(digest);
	return ret;
}

ByteArray MessageDigest::doFinal(ByteArray &data) throw (MessageDigestException, InvalidStateException)
{
	this->update(data);
	return this->doFinal();
}

ByteArray MessageDigest::doFinal(std::string &data) throw (MessageDigestException, InvalidStateException)
{
	this->update(data);
	return this->doFinal();
}

MessageDigest::Algorithm MessageDigest::getAlgorithm() throw (InvalidStateException)
{
	if (this->state == MessageDigest::NO_INIT)
	{
		throw InvalidStateException("MessageDigest::getAlgorithm");
	}
	return this->algorithm;
}

const EVP_MD* MessageDigest::getMessageDigest(MessageDigest::Algorithm algorithm)
{
	const EVP_MD *md;
	md = NULL;
	switch (algorithm)
	{
    // Work only with legacy provider
		//case MessageDigest::MD4:
			//md = EVP_md4();
			//break;
		case MessageDigest::MD5:
			md = EVP_md5();
			break;
    // Work only with legacy provider
		//case MessageDigest::RIPEMD160:
			//md = EVP_ripemd160();
			//break;
		case MessageDigest::SHA1:
			md = EVP_sha1();
			break;
		case MessageDigest::SHA224:
			md = EVP_sha224();
			break;
		case MessageDigest::SHA256:
			md = EVP_sha256();
			break;
		case MessageDigest::SHA384:
			md = EVP_sha384();
			break;
		case MessageDigest::SHA512:
			md = EVP_sha512();
			break;
		case MessageDigest::Identity:
			md = EVP_get_digestbyname("identity_md");
			break;
	}
	return md;
}

ObjectIdentifier MessageDigest::getMessageDigestOid(MessageDigest::Algorithm algorithm) throw (MessageDigestException)
{
	ASN1_OBJECT* asn1object = NULL;
	switch (algorithm)
	{
    // Works only with legacy provider
		//case MessageDigest::MD4:
			//asn1object = OBJ_nid2obj(NID_md4);
			//break;
		case MessageDigest::MD5:
			asn1object = OBJ_nid2obj(NID_md5);
			break;
    // Works only with legacy provider
		//case MessageDigest::RIPEMD160:
			//asn1object = OBJ_nid2obj(NID_ripemd160);
			//break;
		case MessageDigest::SHA1:
			asn1object = OBJ_nid2obj(NID_sha1);
			break;
		case MessageDigest::SHA224:
			asn1object = OBJ_nid2obj(NID_sha224);
			break;
		case MessageDigest::SHA256:
			asn1object = OBJ_nid2obj(NID_sha256);
			break;
		case MessageDigest::SHA384:
			asn1object = OBJ_nid2obj(NID_sha384);
			break;
		case MessageDigest::SHA512:
			asn1object = OBJ_nid2obj(NID_sha512);
			break;
		default:
			throw MessageDigestException(MessageDigestException::INVALID_ALGORITHM, "MessageDigest::getMessageDigest");
	}
	return ObjectIdentifier(asn1object);
}

MessageDigest::Algorithm MessageDigest::getMessageDigest(int algorithmNid)
		throw (MessageDigestException)
{
	MessageDigest::Algorithm ret;
	int nidIdentity = OBJ_sn2nid("identity_md");
	switch (algorithmNid)
	{
		case NID_sha512WithRSAEncryption: case NID_ecdsa_with_SHA512:
			ret = MessageDigest::SHA512;
			break;
		case NID_sha384WithRSAEncryption: case NID_ecdsa_with_SHA384:
			ret = MessageDigest::SHA384;
			break;
		case NID_sha256WithRSAEncryption: case NID_ecdsa_with_SHA256:
			ret = MessageDigest::SHA256;
			break;
		case NID_sha224WithRSAEncryption: case NID_ecdsa_with_SHA224:
			ret = MessageDigest::SHA224;
			break;
		case NID_dsaWithSHA1: case NID_sha1WithRSAEncryption: case NID_sha1WithRSA: case NID_ecdsa_with_SHA1:
    		ret = MessageDigest::SHA1;
    		break;
    	case NID_md5WithRSAEncryption: case NID_md5: case NID_md5WithRSA:
    		ret = MessageDigest::MD5;
    		break;
      // Work only with legacy provider
    	//case NID_md4WithRSAEncryption: case NID_md4:
    		//ret = MessageDigest::MD4;
    		//break;
    	//case NID_ripemd160: case NID_ripemd160WithRSA:
    		//ret = MessageDigest::RIPEMD160;
    		//break;
    	default:
			if (algorithmNid != 0 && algorithmNid == nidIdentity) {
				ret = MessageDigest::Identity;
				break;
			}
    		throw MessageDigestException(MessageDigestException::INVALID_ALGORITHM, "MessageDigest::getMessageDigest");
	}
	return ret;
}

void MessageDigest::loadMessageDigestAlgorithms()
{
	OpenSSL_add_all_digests();
}
