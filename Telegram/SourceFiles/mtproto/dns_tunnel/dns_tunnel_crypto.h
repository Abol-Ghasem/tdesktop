/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <array>

namespace MTP::DnsTunnel {

inline constexpr auto kKeySize = 32;
inline constexpr auto kChatSelectorSize = 3;
inline constexpr auto kChatCounterSize = 3;
inline constexpr auto kChatCellPayloadSize = 19;
inline constexpr auto kChatSealTagSize = 4;
inline constexpr auto kChatBootstrapCounter = 0x400000U;
inline constexpr auto kChatRespCounterBit = 0x800000U;
inline constexpr auto kChatProtocolVersion = 1;

// Opcodes for MTProto tunnel
inline constexpr uint8 kMTPOpOpen = 1;
inline constexpr uint8 kMTPOpData = 2;
inline constexpr uint8 kMTPOpPoll = 3;
inline constexpr uint8 kMTPOpClose = 4;
inline constexpr uint8 kMTPOpDataEnd = 5;

// Status codes
inline constexpr uint8 kMTPStatusOK = 0;
inline constexpr uint8 kMTPStatusNoTunnel = 1;
inline constexpr uint8 kMTPStatusUpstreamClosed = 2;
inline constexpr uint8 kMTPStatusBusy = 3;
inline constexpr uint8 kMTPStatusDisabled = 4;
inline constexpr uint8 kMTPStatusBadRequest = 5;
inline constexpr uint8 kMTPStatusBadDC = 6;

// Key and crypto helpers
void DeriveKeys(
	const QString &passphrase,
	std::array<uint8, 32> &queryKey,
	std::array<uint8, 32> &responseKey);

bool GenerateX25519KeyPair(
	std::array<uint8, 32> &privKey,
	std::array<uint8, 32> &pubKey);

bool ComputeX25519ECDH(
	const std::array<uint8, 32> &privKey,
	const std::array<uint8, 32> &peerPubKey,
	std::array<uint8, 32> &secret);

void DeriveSessionKey(
	const std::array<uint8, 32> &secret,
	const std::array<uint8, 32> &queryKey,
	uint8 protoVer,
	std::array<uint8, 32> &ksession);

void DeriveSealKeys(
	const std::array<uint8, 32> &ksession,
	std::array<uint8, 32> &encKey,
	std::array<uint8, 32> &macKey);

QByteArray SealChat(
	const std::array<uint8, 32> &encKey,
	const std::array<uint8, 32> &macKey,
	const std::array<uint8, 3> &selector,
	uint32 counter,
	const QByteArray &plaintext);

bool OpenChat(
	const std::array<uint8, 32> &encKey,
	const std::array<uint8, 32> &macKey,
	const std::array<uint8, 3> &selector,
	uint32 counter,
	const QByteArray &sealed,
	QByteArray &outPlaintext);

QByteArray SealChatResponse(
	const std::array<uint8, 32> &encKey,
	const std::array<uint8, 32> &macKey,
	const std::array<uint8, 3> &selector,
	uint32 reqCounter,
	uint8 status,
	const QByteArray &body);

bool OpenChatResponse(
	const std::array<uint8, 32> &encKey,
	const std::array<uint8, 32> &macKey,
	const std::array<uint8, 3> &selector,
	uint32 reqCounter,
	const QByteArray &sealed,
	uint8 &outStatus,
	QByteArray &outBody);

QString EncodeChatCell(
	const std::array<uint8, 32> &queryKey,
	const std::array<uint8, 3> &selector,
	uint32 counter,
	const QByteArray &payload,
	const QString &domain);

bool DecodeResponse(
	const std::array<uint8, 32> &responseKey,
	const QString &encodedTxt,
	QByteArray &outData);

QString Base32Encode(const QByteArray &data);
QByteArray Base32Decode(const QString &str);

} // namespace MTP::DnsTunnel
