import json
import select
import socket
import sys


TIMEOUT_SEC = 5


def _socket(bind_addr, bind_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SEC)
    sock.bind((bind_addr, bind_port))
    return sock


def _emit(payload):
    print(json.dumps(payload))


def ping_server(config):
    with _socket(config['bind_addr'], config['bind_port']) as sock:
        data, addr = sock.recvfrom(2048)
        sock.sendto(config.get('reply', 'pong').encode(), addr)
        _emit({
            'received': data.decode(),
            'peer': [addr[0], addr[1]],
        })


def ping_client(config):
    with _socket(config['bind_addr'], config['bind_port']) as sock:
        sock.sendto(
            config.get('payload', 'ping').encode(),
            (config['target_addr'], config['target_port']),
        )
        reply, addr = sock.recvfrom(2048)
        _emit({
            'reply': reply.decode(),
            'peer': [addr[0], addr[1]],
        })


def echo_server(config):
    payloads = []
    target_count = config['count']

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        while len(payloads) < target_count:
            data, addr = sock.recvfrom(2048)
            text = data.decode()
            payloads.append(text)
            sock.sendto(data, addr)

    _emit({'received': payloads})


def echo_client(config):
    payloads = config['payloads']
    echoed = []

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        for payload in payloads:
            sock.sendto(payload.encode(), (config['target_addr'], config['target_port']))

        while len(echoed) < len(payloads):
            reply, _ = sock.recvfrom(2048)
            echoed.append(reply.decode())

    _emit({'sent': payloads, 'echoed': echoed})


def recv_many(config):
    received = []
    target_count = config['count']

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            received.append({
                'message': data.decode(),
                'peer': [addr[0], addr[1]],
            })

    _emit({'received': received})


def send_many(config):
    payloads = config['payloads']
    delay_ms = config.get('delay_ms', 0)

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        for payload in payloads:
            sock.sendto(payload.encode(), (config['target_addr'], config['target_port']))
            if delay_ms:
                import time
                time.sleep(delay_ms / 1000.0)

    _emit({'sent': payloads})


def recv_many_reply(config):
    received = []
    replies = []
    reply_payloads = config.get('replies', [])
    target_count = config['count']

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            message = data.decode()
            index = len(received)
            received.append({
                'message': message,
                'peer': [addr[0], addr[1]],
            })

            if index < len(reply_payloads) and reply_payloads[index] is not None:
                sock.sendto(reply_payloads[index].encode(), addr)
                replies.append({
                    'message': reply_payloads[index],
                    'peer': [addr[0], addr[1]],
                })

    _emit({'received': received, 'replies': replies})


def send_many_recv(config):
    payloads = config['payloads']
    recv_count = config['recv_count']
    replies = []
    delay_ms = config.get('delay_ms', 0)

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        for payload in payloads:
            sock.sendto(payload.encode(), (config['target_addr'], config['target_port']))
            if delay_ms:
                import time
                time.sleep(delay_ms / 1000.0)

        while len(replies) < recv_count:
            data, addr = sock.recvfrom(2048)
            replies.append({
                'message': data.decode(),
                'peer': [addr[0], addr[1]],
            })

    _emit({'sent': payloads, 'replies': replies})


def multi_server(config):
    received = []
    target_count = config['count']
    ack_prefix = config.get('ack_prefix', 'ack:')

    with _socket(config['bind_addr'], config['bind_port']) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            message = data.decode()
            received.append({
                'message': message,
                'peer': [addr[0], addr[1]],
            })
            sock.sendto(f'{ack_prefix}{message}'.encode(), addr)

    _emit({'port': config['bind_port'], 'received': received})


def multi_client(config):
    channels = config['channels']
    bind_addr = config['bind_addr']
    bind_ports = config['bind_ports']
    clients = {}
    replies = []

    for port in bind_ports:
        clients[port] = _socket(bind_addr, port)

    try:
        for channel in channels:
            clients[channel['src_port']].sendto(
                channel['message'].encode(),
                (channel['dst_addr'], channel['dst_port']),
            )

        while len(replies) < len(channels):
            ready, _, _ = select.select(list(clients.values()), [], [], TIMEOUT_SEC)
            if not ready:
                raise TimeoutError('timed out waiting for multi-channel replies')

            for sock in ready:
                data, addr = sock.recvfrom(2048)
                replies.append({
                    'local_port': sock.getsockname()[1],
                    'message': data.decode(),
                    'peer': [addr[0], addr[1]],
                })
    finally:
        for sock in clients.values():
            sock.close()

    _emit({'channels': channels, 'replies': replies})


SCENARIOS = {
    'ping_server': ping_server,
    'ping_client': ping_client,
    'echo_server': echo_server,
    'echo_client': echo_client,
    'recv_many': recv_many,
    'send_many': send_many,
    'recv_many_reply': recv_many_reply,
    'send_many_recv': send_many_recv,
    'multi_server': multi_server,
    'multi_client': multi_client,
}


def main(argv):
    if len(argv) != 3:
        raise SystemExit('usage: udp_scenarios.py <scenario> <json-config>')

    scenario = argv[1]
    config = json.loads(argv[2])
    handler = SCENARIOS.get(scenario)
    if handler is None:
        raise SystemExit(f'unknown scenario: {scenario}')

    handler(config)


if __name__ == '__main__':
    main(sys.argv)
