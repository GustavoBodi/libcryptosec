#include <libcryptosec/AsymmetricCipher.h>

ByteArray AsymmetricCipher::encrypt(RSAPublicKey &key, ByteArray &data, AsymmetricCipher::Padding padding)
		throw (AsymmetricCipherException)
{
	int rsaSize, paddingValue, rc;
	ByteArray ret;
	paddingValue = AsymmetricCipher::getPadding(padding);
	rsaSize = key.getSize();
	ret = ByteArray(rsaSize);
  EVP_PKEY *pkey = key.getEvpPkey();
  RSA *public_key = EVP_PKEY_get1_RSA(key.getEvpPkey());
	rc = RSA_public_encrypt(data.size(), data.getDataPointer(), ret.getDataPointer(), public_key, paddingValue);
	if (rc == -1 || rc != rsaSize)
	{
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");
	}
	return ret;
}

ByteArray AsymmetricCipher::encrypt(RSAPublicKey &key, std::string &data, AsymmetricCipher::Padding padding)
		throw (AsymmetricCipherException)
{
	int rsaSize, paddingValue, rc;
	ByteArray ret;
	paddingValue = AsymmetricCipher::getPadding(padding);
	rsaSize = key.getSize();
	ret = ByteArray(rsaSize);
  EVP_PKEY *pkey = key.getEvpPkey();
  RSA *public_key = EVP_PKEY_get1_RSA(key.getEvpPkey());
	rc = RSA_public_encrypt(data.size(), (const unsigned char *)data.c_str(), ret.getDataPointer(), public_key, paddingValue);
	if (rc == -1 || rc != rsaSize)
	{
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");
	}
	return ret;
}

ByteArray AsymmetricCipher::decrypt(RSAPrivateKey &key, ByteArray &ciphered, AsymmetricCipher::Padding padding)
	throw (AsymmetricCipherException)
{
	int rsaSize, paddingValue, rc;
	ByteArray *retTemp, ret;
	paddingValue = AsymmetricCipher::getPadding(padding);
	rsaSize = key.getSize();
	retTemp = new ByteArray(rsaSize);
  EVP_PKEY *pkey = key.getEvpPkey();
  RSA *private_key = EVP_PKEY_get1_RSA(key.getEvpPkey());
	rc = RSA_private_decrypt(ciphered.size(), ciphered.getDataPointer(), retTemp->getDataPointer(), private_key, paddingValue);
	if (rc <= 0)
	{
		delete retTemp;
		throw AsymmetricCipherException(AsymmetricCipherException::DECRYPTING_DATA, "AsymmetricCipher::decrypt");
	}
	ret = ByteArray(retTemp->getDataPointer(), rc);
	delete retTemp;
	return ret;
}

int AsymmetricCipher::getPadding(AsymmetricCipher::Padding padding)
{
	int ret;
	switch (padding)
	{
		case AsymmetricCipher::NO_PADDING:
			ret = RSA_NO_PADDING;
			break;
		case AsymmetricCipher::PKCS1:
			ret = RSA_PKCS1_PADDING;
			break;
    /* Não deve ser suportado
    / https://github.com/openssl/openssl/issues/14216
    */
		//case AsymmetricCipher::SSLV23:
			//ret = RSA_SSLV23_PADDING;
			//break;
		case AsymmetricCipher::PKCS1_OAEP:
			ret = RSA_PKCS1_OAEP_PADDING;
			break;
//		case AsymmetricCipher::X931:
//			ret = RSA_X931_PADDING;
//			break;
	}
	return ret;
}
