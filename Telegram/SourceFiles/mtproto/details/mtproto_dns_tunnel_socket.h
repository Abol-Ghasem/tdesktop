/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"
#include "mtproto/mtproto_proxy_data.h"
#include "mtproto/dns_tunnel/dns_tunnel_crypto.h"

#include <QtCore/QByteArray>
#include <QtCore/QTimer>
#include <QtNetwork/QUdpSocket>
#include <QtNetwork/QHostAddress>
#include <deque>

namespace MTP::details {

class DnsTunnelSocket final : public AbstractSocket {
public:
	DnsTunnelSocket(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		int16 protocolDcId);
	~DnsTunnelSocket();

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;

private:
	enum class State {
		NotConnected,
		Handshaking,
		Opening,
		Connected,
		Disconnected,
		Error,
	};

	void initKeys();
	void startHandshake();
	void sendHandshakeFragment(int index);
	void sendOpOpen();
	void sendOpPoll();
	void pumpOutgoing();
	void sendDnsQuery(const QString &qname, uint32 counter, int retry = 0);

	void onUdpReadyRead();
	void processDnsResponse(const QByteArray &packet);
	void onHandshakeReply(const QByteArray &body);
	void onOpenReply(const QByteArray &body);
	void onDataOrPollReply(const QByteArray &body);

	void onPollTimeout();
	void onRetransmitTimeout();

	void transitionToDisconnected();
	void transitionToError();

	const ProxyData _proxy;
	const int16 _dcId;
	State _state = State::NotConnected;

	std::unique_ptr<QUdpSocket> _udp;
	QHostAddress _dnsServer;
	uint16 _dnsPort = 53;
	QString _tunnelDomain;

	std::array<uint8, 32> _queryKey{};
	std::array<uint8, 32> _responseKey{};
	std::array<uint8, 32> _serverEk{};
	std::array<uint8, 32> _ksession{};
	std::array<uint8, 32> _sealEncKey{};
	std::array<uint8, 32> _sealMacKey{};
	bool _hasKsession = false;

	std::array<uint8, 32> _ephPriv{};
	std::array<uint8, 32> _ephPub{};
	std::array<uint8, 3> _setupTag{};
	int _handshakeFragmentsSent = 0;

	std::array<uint8, 3> _sessionRef{};
	uint32 _counter = 0;
	uint8 _chunkSize = 13;

	uint16 _upSeq = 0;
	uint16 _downAck = 0;

	QByteArray _outQueue;
	QByteArray _incoming;
	int _incomingOffset = 0;

	QTimer _pollTimer;
	QTimer _retransmitTimer;

	struct InFlightQuery {
		uint16 txId = 0;
		QString qname;
		uint32 counter = 0;
		qint64 sendTime = 0;
		int retries = 0;
	};
	std::deque<InFlightQuery> _inFlight;

	uint16 _dnsTxId = 1;

};

} // namespace MTP::details
