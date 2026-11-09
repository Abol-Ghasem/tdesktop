/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/dns_tunnel/dns_tunnel_crypto.h"

#include <QtCore/QtEndian>
#include <QtCore/QCryptographicHash>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <algorithm>

namespace MTP::DnsTunnel {
namespace {

const char kBase32Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void HmacSha256(
		const void *key,
		int keyLen,
		const void *data,
		int dataLen,
		void *out32) {
	unsigned int len = 32;
	HMAC(
		EVP_sha256(),
		key,
		keyLen,
		static_cast<const unsigned char*>(data),
		dataLen,
		static_cast<unsigned char*>(out32),
		&len);
}

void HkdfExtractAndExpand(
		const void *salt,
		int saltLen,
		const void *ikm,
		int ikmLen,
		const void *info,
		int infoLen,
		void *okm,
		int okmLen) {
	unsigned char prk[32];
	if (!salt || saltLen == 0) {
		unsigned char zeroSalt[32] = { 0 };
		HmacSha256(zeroSalt, 32, ikm, ikmLen, prk);
	} else {
		HmacSha256(salt, saltLen, ikm, ikmLen, prk);
	}

	unsigned char t[32] = { 0 };
	int tLen = 0;
	int generated = 0;
	unsigned char counter = 1;
	unsigned char *outPtr = static_cast<unsigned char*>(okm);

	while (generated < okmLen) {
		HMAC_CTX *ctx = HMAC_CTX_new();
		HMAC_Init_ex(ctx, prk, 32, EVP_sha256(), nullptr);
		if (tLen > 0) {
			HMAC_Update(ctx, t, tLen);
		}
		if (info && infoLen > 0) {
			HMAC_Update(ctx, static_cast<const unsigned char*>(info), infoLen);
		}
		HMAC_Update(ctx, &counter, 1);
		unsigned int outLen = 32;
		HMAC_Final(ctx, t, &outLen);
		HMAC_CTX_free(ctx);

		tLen = 32;
		const auto toCopy = std::min<int>(32, okmLen - generated);
		memcpy(outPtr + generated, t, toCopy);
		generated += toCopy;
		counter++;
	}
}

std::array<uint8, 16> MakeChatSealNonce(
		const std::array<uint8, 3> &selector,
		uint32 counter) {
	std::array<uint8, 16> nonce{};
	nonce[0] = selector[0];
	nonce[1] = selector[1];
	nonce[2] = selector[2];
	nonce[3] = 0;
	qToBigEndian(counter, nonce.data() + 4);
	return nonce;
}

QByteArray AesCtrCrypt(
		const std::array<uint8, 32> &key,
		const std::array<uint8, 16> &nonce,
		const QByteArray &data) {
	if (data.isEmpty()) {
		return {};
	}
	QByteArray result(data.size(), Qt::Uninitialized);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(
		ctx,
		EVP_aes_256_ctr(),
		nullptr,
		key.data(),
		nonce.data());
	int outLen = 0;
	EVP_EncryptUpdate(
		ctx,
		reinterpret_cast<unsigned char*>(result.data()),
		&outLen,
		reinterpret_cast<const unsigned char*>(data.constData()),
		data.size());
	int finalLen = 0;
	EVP_EncryptFinal_ex(
		ctx,
		reinterpret_cast<unsigned char*>(result.data()) + outLen,
		&finalLen);
	EVP_CIPHER_CTX_free(ctx);
	return result;
}

} // namespace

void DeriveKeys(
		const QString &passphrase,
		std::array<uint8, 32> &queryKey,
		std::array<uint8, 32> &responseKey) {
	const auto masterHash = QCryptographicHash::hash(
		passphrase.toUtf8(),
		QCryptographicHash::Sha256);

	const char queryInfo[] = "thefeed-query";
	HkdfExtractAndExpand(
		nullptr,
		0,
		masterHash.constData(),
		masterHash.size(),
		queryInfo,
		sizeof(queryInfo) - 1,
		queryKey.data(),
		32);

	const char respInfo[] = "thefeed-response";
	HkdfExtractAndExpand(
		nullptr,
		0,
		masterHash.constData(),
		masterHash.size(),
		respInfo,
		sizeof(respInfo) - 1,
		responseKey.data(),
		32);
}

bool GenerateX25519KeyPair(
		std::array<uint8, 32> &privKey,
		std::array<uint8, 32> &pubKey) {
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, nullptr);
	if (!pctx) {
		return false;
	}
	if (EVP_PKEY_keygen_init(pctx) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	EVP_PKEY *pkey = nullptr;
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(pctx);
		return false;
	}
	size_t pubLen = 32;
	size_t privLen = 32;
	EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &pubLen);
	EVP_PKEY_get_raw_private_key(pkey, privKey.data(), &privLen);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return true;
}

bool ComputeX25519ECDH(
		const std::array<uint8, 32> &privKey,
		const std::array<uint8, 32> &peerPubKey,
		std::array<uint8, 32> &secret) {
	EVP_PKEY *ownKey = EVP_PKEY_new_raw_private_key(
		NID_X25519,
		nullptr,
		privKey.data(),
		32);
	if (!ownKey) {
		return false;
	}
	EVP_PKEY *peerKey = EVP_PKEY_new_raw_public_key(
		NID_X25519,
		nullptr,
		peerPubKey.data(),
		32);
	if (!peerKey) {
		EVP_PKEY_free(ownKey);
		return false;
	}
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ownKey, nullptr);
	bool ok = false;
	if (ctx
		&& EVP_PKEY_derive_init(ctx) > 0
		&& EVP_PKEY_derive_set_peer(ctx, peerKey) > 0) {
		size_t len = 32;
		if (EVP_PKEY_derive(ctx, secret.data(), &len) > 0 && len == 32) {
			ok = true;
		}
	}
	if (ctx) {
		EVP_PKEY_CTX_free(ctx);
	}
	EVP_PKEY_free(peerKey);
	EVP_PKEY_free(ownKey);
	return ok;
}

void DeriveSessionKey(
		const std::array<uint8, 32> &secret,
		const std::array<uint8, 32> &queryKey,
		uint8 protoVer,
		std::array<uint8, 32> &ksession) {
	const char ctxInfo[] = "thefeed-mtproto-session-v1";
	QByteArray info;
	info.append(ctxInfo, sizeof(ctxInfo) - 1);
	info.append(static_cast<char>(protoVer));
	info.append(reinterpret_cast<const char*>(queryKey.data()), 32);

	HkdfExtractAndExpand(
		nullptr,
		0,
		secret.data(),
		32,
		info.constData(),
		info.size(),
		ksession.data(),
		32);
}

void DeriveSealKeys(
		const std::array<uint8, 32> &ksession,
		std::array<uint8, 32> &encKey,
		std::array<uint8, 32> &macKey) {
	const char encInfo[] = "thefeed-chat-seal-enc-v1";
	HkdfExtractAndExpand(
		nullptr,
		0,
		ksession.data(),
		32,
		encInfo,
		sizeof(encInfo) - 1,
		encKey.data(),
		32);

	const char macInfo[] = "thefeed-chat-seal-mac-v1";
	HkdfExtractAndExpand(
		nullptr,
		0,
		ksession.data(),
		32,
		macInfo,
		sizeof(macInfo) - 1,
		macKey.data(),
		32);
}

QByteArray SealChat(
		const std::array<uint8, 32> &encKey,
		const std::array<uint8, 32> &macKey,
		const std::array<uint8, 3> &selector,
		uint32 counter,
		const QByteArray &plaintext) {
	const auto nonce = MakeChatSealNonce(selector, counter);
	const auto ct = AesCtrCrypt(encKey, nonce, plaintext);

	QByteArray toMac;
	toMac.append(reinterpret_cast<const char*>(nonce.data()), 16);
	toMac.append(ct);

	unsigned char mac[32];
	HmacSha256(macKey.data(), 32, toMac.constData(), toMac.size(), mac);

	QByteArray out = ct;
	out.append(reinterpret_cast<const char*>(mac), kChatSealTagSize);
	return out;
}

bool OpenChat(
		const std::array<uint8, 32> &encKey,
		const std::array<uint8, 32> &macKey,
		const std::array<uint8, 3> &selector,
		uint32 counter,
		const QByteArray &sealed,
		QByteArray &outPlaintext) {
	if (sealed.size() < kChatSealTagSize) {
		return false;
	}
	const auto ctLen = sealed.size() - kChatSealTagSize;
	const auto ct = sealed.left(ctLen);
	const auto tag = sealed.mid(ctLen, kChatSealTagSize);

	const auto nonce = MakeChatSealNonce(selector, counter);

	QByteArray toMac;
	toMac.append(reinterpret_cast<const char*>(nonce.data()), 16);
	toMac.append(ct);

	unsigned char mac[32];
	HmacSha256(macKey.data(), 32, toMac.constData(), toMac.size(), mac);

	if (memcmp(mac, tag.constData(), kChatSealTagSize) != 0) {
		return false;
	}

	outPlaintext = AesCtrCrypt(encKey, nonce, ct);
	return true;
}

QByteArray SealChatResponse(
		const std::array<uint8, 32> &encKey,
		const std::array<uint8, 32> &macKey,
		const std::array<uint8, 3> &selector,
		uint32 reqCounter,
		uint8 status,
		const QByteArray &body) {
	QByteArray pt;
	pt.append(static_cast<char>(status));
	pt.append(body);
	return SealChat(
		encKey,
		macKey,
		selector,
		reqCounter | kChatRespCounterBit,
		pt);
}

bool OpenChatResponse(
		const std::array<uint8, 32> &encKey,
		const std::array<uint8, 32> &macKey,
		const std::array<uint8, 3> &selector,
		uint32 reqCounter,
		const QByteArray &sealed,
		uint8 &outStatus,
		QByteArray &outBody) {
	QByteArray pt;
	if (!OpenChat(
		encKey,
		macKey,
		selector,
		reqCounter | kChatRespCounterBit,
		sealed,
		pt)) {
		return false;
	}
	if (pt.isEmpty()) {
		return false;
	}
	outStatus = static_cast<uint8>(pt[0]);
	outBody = pt.mid(1);
	return true;
}

QString EncodeChatCell(
		const std::array<uint8, 32> &queryKey,
		const std::array<uint8, 3> &selector,
		uint32 counter,
		const QByteArray &payload,
		const QString &domain) {
	const char maskInfo[] = "thefeed-chat-cell-mask-v1";
	QByteArray toMask;
	toMask.append(maskInfo, sizeof(maskInfo) - 1);
	toMask.append(payload);

	unsigned char mask[32];
	HmacSha256(queryKey.data(), 32, toMask.constData(), toMask.size(), mask);

	QByteArray raw;
	raw.resize(kChatSelectorSize + kChatCounterSize + payload.size());

	raw[0] = static_cast<char>(selector[0] ^ mask[0]);
	raw[1] = static_cast<char>(selector[1] ^ mask[1]);
	raw[2] = static_cast<char>(selector[2] ^ mask[2]);

	raw[3] = static_cast<char>(((counter >> 16) & 0xFF) ^ mask[3]);
	raw[4] = static_cast<char>(((counter >> 8) & 0xFF) ^ mask[4]);
	raw[5] = static_cast<char>((counter & 0xFF) ^ mask[5]);

	memcpy(
		raw.data() + kChatSelectorSize + kChatCounterSize,
		payload.constData(),
		payload.size());

	const auto label = Base32Encode(raw).toLower();
	auto cleanDomain = domain;
	if (cleanDomain.endsWith('.')) {
		cleanDomain.chop(1);
	}
	return label + "." + cleanDomain;
}

bool DecodeResponse(
		const std::array<uint8, 32> &responseKey,
		const QString &encodedTxt,
		QByteArray &outData) {
	const auto ciphertext = QByteArray::fromBase64(encodedTxt.toUtf8());
	if (ciphertext.size() < 12 + 16) {
		// Not encrypted with GCM, or direct response
		outData = ciphertext;
		return !outData.isEmpty();
	}

	const auto nonce = reinterpret_cast<const unsigned char*>(ciphertext.constData());
	const auto tag = reinterpret_cast<const unsigned char*>(ciphertext.constData() + ciphertext.size() - 16);
	const auto ct = reinterpret_cast<const unsigned char*>(ciphertext.constData() + 12);
	const auto ctLen = ciphertext.size() - 12 - 16;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
	EVP_DecryptInit_ex(ctx, nullptr, nullptr, responseKey.data(), nonce);

	QByteArray plain(ctLen, Qt::Uninitialized);
	int outLen = 0;
	EVP_DecryptUpdate(
		ctx,
		reinterpret_cast<unsigned char*>(plain.data()),
		&outLen,
		ct,
		ctLen);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char*>(tag));

	int finalLen = 0;
	const auto ret = EVP_DecryptFinal_ex(
		ctx,
		reinterpret_cast<unsigned char*>(plain.data()) + outLen,
		&finalLen);
	EVP_CIPHER_CTX_free(ctx);

	if (ret <= 0) {
		// If GCM decryption failed with key, test if ciphertext was direct
		outData = ciphertext;
		return true;
	}

	if (plain.size() < 2) {
		return false;
	}
	const auto dataLen = (static_cast<uint8>(plain[0]) << 8) | static_cast<uint8>(plain[1]);
	if (dataLen > plain.size() - 2) {
		return false;
	}
	outData = plain.mid(2, dataLen);
	return true;
}

QString Base32Encode(const QByteArray &data) {
	QString result;
	int buffer = 0;
	int bitsLeft = 0;

	for (const auto byte : data) {
		buffer = (buffer << 8) | (static_cast<unsigned char>(byte) & 0xFF);
		bitsLeft += 8;
		while (bitsLeft >= 5) {
			bitsLeft -= 5;
			result.append(QChar(kBase32Chars[(buffer >> bitsLeft) & 0x1F]));
		}
	}
	if (bitsLeft > 0) {
		buffer <<= (5 - bitsLeft);
		result.append(QChar(kBase32Chars[buffer & 0x1F]));
	}
	return result;
}

QByteArray Base32Decode(const QString &str) {
	QByteArray result;
	int buffer = 0;
	int bitsLeft = 0;

	for (const auto ch : str.toUpper()) {
		const auto c = ch.toLatin1();
		int val = -1;
		if (c >= 'A' && c <= 'Z') {
			val = c - 'A';
		} else if (c >= '2' && c <= '7') {
			val = c - '2' + 26;
		}
		if (val >= 0) {
			buffer = (buffer << 5) | val;
			bitsLeft += 5;
			if (bitsLeft >= 8) {
				bitsLeft -= 8;
				result.append(static_cast<char>((buffer >> bitsLeft) & 0xFF));
			}
		}
	}
	return result;
}

} // namespace MTP::DnsTunnel
