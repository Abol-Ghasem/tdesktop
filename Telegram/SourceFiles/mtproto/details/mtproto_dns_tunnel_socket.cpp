/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/details/mtproto_dns_tunnel_socket.h"

#include <QtCore/QtEndian>
#include <QtCore/QDateTime>
#include <openssl/rand.h>

namespace MTP::details {
namespace {

using namespace DnsTunnel;

QByteArray BuildDnsQueryPacket(uint16 txId, const QString &qname) {
	QByteArray packet;
	packet.resize(12);
	qToBigEndian(txId, packet.data());
	qToBigEndian(uint16(0x0100), packet.data() + 2); // RD = 1
	qToBigEndian(uint16(1), packet.data() + 4);      // QDCOUNT = 1
	qToBigEndian(uint16(0), packet.data() + 6);      // ANCOUNT = 0
	qToBigEndian(uint16(0), packet.data() + 8);      // NSCOUNT = 0
	qToBigEndian(uint16(0), packet.data() + 10);     // ARCOUNT = 0

	const auto parts = qname.split('.', Qt::SkipEmptyParts);
	for (const auto &part : parts) {
		const auto utf8 = part.toUtf8();
		packet.append(static_cast<char>(utf8.size()));
		packet.append(utf8);
	}
	packet.append('\0'); // Root label

	// QTYPE = TXT (16), QCLASS = IN (1)
	char qtypeAndClass[4];
	qToBigEndian(uint16(16), qtypeAndClass);
	qToBigEndian(uint16(1), qtypeAndClass + 2);
	packet.append(qtypeAndClass, 4);

	return packet;
}

QString ExtractDnsTxtRecord(const QByteArray &packet) {
	if (packet.size() < 12) {
		return QString();
	}
	const auto flags = qFromBigEndian<uint16>(packet.constData() + 2);
	if (!(flags & 0x8000)) { // QR bit
		return QString();
	}
	const auto ancount = qFromBigEndian<uint16>(packet.constData() + 6);
	if (ancount == 0) {
		return QString();
	}

	int offset = 12;
	// Skip question
	while (offset < packet.size()) {
		const auto len = static_cast<uint8>(packet[offset]);
		if (len == 0) {
			offset += 5; // \0 + QTYPE(2) + QCLASS(2)
			break;
		} else if ((len & 0xC0) == 0xC0) {
			offset += 6; // Pointer(2) + QTYPE(2) + QCLASS(2)
			break;
		}
		offset += 1 + len;
	}

	// Parse answers
	for (int i = 0; i < ancount && offset < packet.size(); ++i) {
		// Skip NAME
		if ((static_cast<uint8>(packet[offset]) & 0xC0) == 0xC0) {
			offset += 2;
		} else {
			while (offset < packet.size() && packet[offset] != 0) {
				offset += 1 + static_cast<uint8>(packet[offset]);
			}
			offset += 1;
		}
		if (offset + 10 > packet.size()) {
			break;
		}
		const auto type = qFromBigEndian<uint16>(packet.constData() + offset);
		const auto rdlen = qFromBigEndian<uint16>(packet.constData() + offset + 8);
		offset += 10;

		if (type == 16 && offset + rdlen <= packet.size()) { // TXT
			QByteArray txtData;
			int rdoff = offset;
			const int end = offset + rdlen;
			while (rdoff < end) {
				const auto slen = static_cast<uint8>(packet[rdoff++]);
				if (rdoff + slen > end) {
					break;
				}
				txtData.append(packet.mid(rdoff, slen));
				rdoff += slen;
			}
			return QString::fromUtf8(txtData);
		}
		offset += rdlen;
	}
	return QString();
}

} // namespace

DnsTunnelSocket::DnsTunnelSocket(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		int16 protocolDcId)
: AbstractSocket(thread)
, _proxy(proxy)
, _dcId(protocolDcId > 0 ? protocolDcId : 2) {
	_tunnelDomain = _proxy.host;
	_dnsPort = _proxy.port ? _proxy.port : 53;

	const auto customDns = _proxy.user.trimmed();
	if (!customDns.isEmpty() && _dnsServer.setAddress(customDns)) {
		// Use user-specified DNS server IP
	} else {
		_dnsServer = QHostAddress(QStringLiteral("8.8.8.8"));
	}

	initKeys();

	connect(&_pollTimer, &QTimer::timeout, [this] { onPollTimeout(); });
	connect(&_retransmitTimer, &QTimer::timeout, [this] { onRetransmitTimeout(); });
}

DnsTunnelSocket::~DnsTunnelSocket() {
	_pollTimer.stop();
	_retransmitTimer.stop();
	if (_udp) {
		_udp->close();
	}
}

void DnsTunnelSocket::initKeys() {
	auto secretText = _proxy.password.trimmed();
	QString passphrase;
	if (secretText.contains(';')) {
		const auto parts = secretText.split(';');
		secretText = parts[0].trimmed();
		passphrase = parts[1].trimmed();
	}
	DnsTunnel::DeriveKeys(passphrase, _queryKey, _responseKey);

	// Parse server public key from password
	const auto hexSecret = QByteArray::fromHex(secretText.toUtf8());
	if (hexSecret.size() == 32) {
		memcpy(_serverEk.data(), hexSecret.constData(), 32);
	} else {
		const auto b64Secret = QByteArray::fromBase64(secretText.toUtf8());
		if (b64Secret.size() == 32) {
			memcpy(_serverEk.data(), b64Secret.constData(), 32);
		} else {
			RAND_bytes(_serverEk.data(), 32);
		}
	}
}

void DnsTunnelSocket::connectToHost(const QString &, int) {
	Expects(_state == State::NotConnected);

	_state = State::Handshaking;
	_udp = std::make_unique<QUdpSocket>();
	connect(_udp.get(), &QUdpSocket::readyRead, [this] {
		onUdpReadyRead();
	});

	startHandshake();
}

void DnsTunnelSocket::startHandshake() {
	if (!DnsTunnel::GenerateX25519KeyPair(_ephPriv, _ephPub)) {
		transitionToError();
		return;
	}

	std::array<uint8, 32> sharedSecret{};
	if (!DnsTunnel::ComputeX25519ECDH(_ephPriv, _serverEk, sharedSecret)) {
		transitionToError();
		return;
	}

	DnsTunnel::DeriveSessionKey(
		sharedSecret,
		_queryKey,
		kChatProtocolVersion,
		_ksession);
	DnsTunnel::DeriveSealKeys(_ksession, _sealEncKey, _sealMacKey);
	_hasKsession = true;

	RAND_bytes(_setupTag.data(), 3);
	_setupTag[0] |= 0x80; // Handshake bit

	_handshakeFragmentsSent = 0;
	sendHandshakeFragment(0);
	sendHandshakeFragment(1);

	_retransmitTimer.start(2000);
}

void DnsTunnelSocket::sendHandshakeFragment(int index) {
	QByteArray payload(kChatCellPayloadSize, Qt::Uninitialized);
	if (index == 0) {
		memcpy(payload.data(), _ephPub.data(), kChatCellPayloadSize);
	} else {
		memcpy(payload.data(), _ephPub.data() + kChatCellPayloadSize, 13);
		RAND_bytes(reinterpret_cast<unsigned char*>(payload.data() + 13), 6);
	}

	const auto qname = DnsTunnel::EncodeChatCell(
		_queryKey,
		_setupTag,
		uint32(index),
		payload,
		_tunnelDomain);

	sendDnsQuery(qname, uint32(index));
}

void DnsTunnelSocket::sendOpOpen() {
	_state = State::Opening;

	QByteArray payload;
	payload.append(static_cast<char>(kMTPOpOpen));
	payload.append(static_cast<char>(_dcId));

	// Pad to uniform budget (15 bytes)
	while (payload.size() < 15) {
		payload.append('\0');
	}

	const auto sealed = DnsTunnel::SealChat(
		_sealEncKey,
		_sealMacKey,
		_sessionRef,
		_counter,
		payload);

	const auto qname = DnsTunnel::EncodeChatCell(
		_queryKey,
		_sessionRef,
		_counter,
		sealed,
		_tunnelDomain);

	sendDnsQuery(qname, _counter);
	_counter++;
}

void DnsTunnelSocket::sendOpPoll() {
	if (_state != State::Connected) {
		return;
	}

	QByteArray payload;
	payload.append(static_cast<char>(kMTPOpPoll));
	char ackBytes[2];
	qToBigEndian(_downAck, ackBytes);
	payload.append(ackBytes, 2);

	while (payload.size() < 15) {
		payload.append('\0');
	}

	const auto sealed = DnsTunnel::SealChat(
		_sealEncKey,
		_sealMacKey,
		_sessionRef,
		_counter,
		payload);

	const auto qname = DnsTunnel::EncodeChatCell(
		_queryKey,
		_sessionRef,
		_counter,
		sealed,
		_tunnelDomain);

	sendDnsQuery(qname, _counter);
	_counter++;
}

void DnsTunnelSocket::pumpOutgoing() {
	if (_state != State::Connected || _outQueue.isEmpty()) {
		return;
	}

	while (!_outQueue.isEmpty() && _inFlight.size() < 3) {
		const auto take = std::min<int>(int(_chunkSize), int(_outQueue.size()));
		const auto chunk = _outQueue.left(take);
		_outQueue.remove(0, take);

		const auto op = _outQueue.isEmpty() ? kMTPOpDataEnd : kMTPOpData;

		QByteArray payload;
		payload.append(static_cast<char>(op));
		char seqBytes[4];
		qToBigEndian(_upSeq, seqBytes);
		qToBigEndian(_downAck, seqBytes + 2);
		payload.append(seqBytes, 4);
		payload.append(chunk);

		const auto sealed = DnsTunnel::SealChat(
			_sealEncKey,
			_sealMacKey,
			_sessionRef,
			_counter,
			payload);

		const auto qname = DnsTunnel::EncodeChatCell(
			_queryKey,
			_sessionRef,
			_counter,
			sealed,
			_tunnelDomain);

		sendDnsQuery(qname, _counter);
		_upSeq += take;
		_counter++;
	}
}

void DnsTunnelSocket::sendDnsQuery(const QString &qname, uint32 counter, int retry) {
	if (!_udp) {
		return;
	}
	const auto txId = _dnsTxId++;
	const auto packet = BuildDnsQueryPacket(txId, qname);
	_udp->writeDatagram(packet, _dnsServer, _dnsPort);

	InFlightQuery item;
	item.txId = txId;
	item.qname = qname;
	item.counter = counter;
	item.sendTime = QDateTime::currentMSecsSinceEpoch();
	item.retries = retry;
	_inFlight.push_back(item);
}

void DnsTunnelSocket::onUdpReadyRead() {
	while (_udp && _udp->hasPendingDatagrams()) {
		QByteArray datagram;
		datagram.resize(int(_udp->pendingDatagramSize()));
		_udp->readDatagram(datagram.data(), datagram.size());
		processDnsResponse(datagram);
	}
}

void DnsTunnelSocket::processDnsResponse(const QByteArray &packet) {
	if (_inFlight.empty() || packet.size() < 12) {
		return;
	}
	const auto txId = qFromBigEndian<uint16>(packet.constData());
	const auto it = std::find_if(_inFlight.begin(), _inFlight.end(), [txId](const InFlightQuery &q) {
		return q.txId == txId;
	});
	if (it == _inFlight.end()) {
		return;
	}

	const auto query = *it;
	_inFlight.erase(it);

	const auto txt = ExtractDnsTxtRecord(packet);
	if (txt.isEmpty()) {
		return;
	}

	QByteArray decrypted;
	if (!DnsTunnel::DecodeResponse(_responseKey, txt, decrypted)) {
		return;
	}

	uint8 status = 0;
	QByteArray body;

	if (_state == State::Handshaking) {
		if (DnsTunnel::OpenChatResponse(
			_sealEncKey,
			_sealMacKey,
			_setupTag,
			kChatBootstrapCounter,
			decrypted,
			status,
			body)) {
			onHandshakeReply(body);
		}
	} else if (_state == State::Opening) {
		if (DnsTunnel::OpenChatResponse(
			_sealEncKey,
			_sealMacKey,
			_sessionRef,
			query.counter,
			decrypted,
			status,
			body)) {
			onOpenReply(body);
		}
	} else if (_state == State::Connected) {
		if (DnsTunnel::OpenChatResponse(
			_sealEncKey,
			_sealMacKey,
			_sessionRef,
			query.counter,
			decrypted,
			status,
			body)) {
			onDataOrPollReply(body);
		}
	}
}

void DnsTunnelSocket::onHandshakeReply(const QByteArray &body) {
	if (body.size() < 5) {
		transitionToError();
		return;
	}
	const auto status = static_cast<uint8>(body[0]);
	if (status != kMTPStatusOK) {
		transitionToError();
		return;
	}
	_sessionRef[0] = static_cast<uint8>(body[1]);
	_sessionRef[1] = static_cast<uint8>(body[2]);
	_sessionRef[2] = static_cast<uint8>(body[3]);
	_chunkSize = static_cast<uint8>(body[4]);
	if (_chunkSize < 3) {
		_chunkSize = 13;
	}
	_counter = 0;
	sendOpOpen();
}

void DnsTunnelSocket::onOpenReply(const QByteArray &body) {
	if (body.isEmpty()) {
		transitionToError();
		return;
	}
	const auto status = static_cast<uint8>(body[0]);
	if (status != kMTPStatusOK) {
		transitionToError();
		return;
	}
	_state = State::Connected;
	_pollTimer.start(1000);
	_connected.fire({});
	pumpOutgoing();
}

void DnsTunnelSocket::onDataOrPollReply(const QByteArray &body) {
	if (body.size() < 7) {
		return;
	}
	const auto status = static_cast<uint8>(body[0]);
	if (status == kMTPStatusNoTunnel) {
		// Session expired on server; restart handshake
		_state = State::Handshaking;
		startHandshake();
		return;
	} else if (status == kMTPStatusUpstreamClosed) {
		transitionToDisconnected();
		return;
	}

	const auto upAck = qFromBigEndian<uint16>(body.constData() + 1);
	(void)upAck;
	const auto downSeq = qFromBigEndian<uint16>(body.constData() + 3);
	const auto downLeft = qFromBigEndian<uint16>(body.constData() + 5);
	const auto data = body.mid(7);

	if (!data.isEmpty()) {
		_incoming.append(data);
		_downAck = downSeq + uint16(data.size());
		_readyRead.fire({});
	}

	if (downLeft > 0) {
		sendOpPoll();
	}

	if (!_outQueue.isEmpty()) {
		pumpOutgoing();
	}
}

void DnsTunnelSocket::onPollTimeout() {
	if (_state == State::Connected && _inFlight.empty()) {
		sendOpPoll();
	}
}

void DnsTunnelSocket::onRetransmitTimeout() {
	const auto now = QDateTime::currentMSecsSinceEpoch();
	for (auto &query : _inFlight) {
		if (now - query.sendTime > 2500) {
			if (query.retries < 3) {
				query.retries++;
				query.sendTime = now;
				query.txId = _dnsTxId++;
				const auto packet = BuildDnsQueryPacket(query.txId, query.qname);
				if (_udp) {
					_udp->writeDatagram(packet, _dnsServer, _dnsPort);
				}
			}
		}
	}
}

void DnsTunnelSocket::transitionToDisconnected() {
	if (_state == State::Disconnected || _state == State::Error) {
		return;
	}
	_state = State::Disconnected;
	_pollTimer.stop();
	_retransmitTimer.stop();
	_disconnected.fire({});
}

void DnsTunnelSocket::transitionToError() {
	if (_state == State::Disconnected || _state == State::Error) {
		return;
	}
	_state = State::Error;
	_pollTimer.stop();
	_retransmitTimer.stop();
	_error.fire({});
}

bool DnsTunnelSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto bytes = nonce.data();
	const auto zero = gsl::to_integer<uchar>(nonce.front());
	const auto first = qFromUnaligned<uint32>(bytes);
	const auto second = qFromUnaligned<uint32>(bytes + sizeof(uint32));
	return (zero != 0xEFU)
		&& (first != 0x44414548U)
		&& (first != 0x54534F50U)
		&& (first != 0x20544547U)
		&& (first != 0xEEEEEEEEU)
		&& (first != 0xDDDDDDDDU)
		&& (first != 0x02010316U)
		&& (second != 0x00000000U);
}

void DnsTunnelSocket::timedOut() {
}

bool DnsTunnelSocket::isConnected() {
	return (_state == State::Connected);
}

bool DnsTunnelSocket::hasBytesAvailable() {
	return (_incomingOffset < _incoming.size());
}

int64 DnsTunnelSocket::read(bytes::span buffer) {
	const auto available = _incoming.size() - _incomingOffset;
	if (available <= 0) {
		return 0;
	}
	const auto count = int(std::min<std::size_t>(available, buffer.size()));
	if (!count) {
		return 0;
	}
	bytes::copy(
		buffer,
		bytes::make_span(_incoming).subspan(_incomingOffset, count));
	_incomingOffset += count;
	if (_incomingOffset == _incoming.size()) {
		_incoming.clear();
		_incomingOffset = 0;
	} else if (_incomingOffset >= 64 * 1024
		&& _incomingOffset >= _incoming.size() / 2) {
		_incoming.remove(0, _incomingOffset);
		_incomingOffset = 0;
	}
	return count;
}

void DnsTunnelSocket::write(
		bytes::const_span prefix,
		bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (!prefix.empty()) {
		_outQueue.append(
			reinterpret_cast<const char*>(prefix.data()),
			prefix.size());
	}
	_outQueue.append(
		reinterpret_cast<const char*>(buffer.data()),
		buffer.size());

	pumpOutgoing();
}

int32 DnsTunnelSocket::debugState() {
	return int32(_state);
}

QString DnsTunnelSocket::debugPostfix() const {
	return u"_dnstunnel"_q;
}

} // namespace MTP::details
