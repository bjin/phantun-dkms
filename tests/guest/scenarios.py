import json
import select
import socket
import struct
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
    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        data, addr = sock.recvfrom(2048)
        sock.sendto(config.get("reply", "pong").encode(), addr)
        _emit(
            {
                "received": data.decode(),
                "peer": [addr[0], addr[1]],
            }
        )


def ping_client(config):
    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        sock.sendto(
            config.get("payload", "ping").encode(),
            (config["target_addr"], config["target_port"]),
        )
        reply, addr = sock.recvfrom(2048)
        _emit(
            {
                "reply": reply.decode(),
                "peer": [addr[0], addr[1]],
            }
        )


def echo_server(config):
    payloads = []
    target_count = config["count"]

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        while len(payloads) < target_count:
            data, addr = sock.recvfrom(2048)
            text = data.decode()
            payloads.append(text)
            sock.sendto(data, addr)

    _emit({"received": payloads})


def echo_client(config):
    payloads = config["payloads"]
    echoed = []

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        for payload in payloads:
            sock.sendto(
                payload.encode(), (config["target_addr"], config["target_port"])
            )

        while len(echoed) < len(payloads):
            reply, _ = sock.recvfrom(2048)
            echoed.append(reply.decode())

    _emit({"sent": payloads, "echoed": echoed})


def recv_many(config):
    received = []
    target_count = config["count"]

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            received.append(
                {
                    "message": data.decode(),
                    "peer": [addr[0], addr[1]],
                }
            )

    _emit({"received": received})


def send_many(config):
    payloads = config["payloads"]
    delay_ms = config.get("delay_ms", 0)

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        for payload in payloads:
            sock.sendto(
                payload.encode(), (config["target_addr"], config["target_port"])
            )
            if delay_ms:
                import time

                time.sleep(delay_ms / 1000.0)

    _emit({"sent": payloads})


def recv_many_reply(config):
    received = []
    replies = []
    reply_payloads = config.get("replies", [])
    target_count = config["count"]

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            message = data.decode()
            index = len(received)
            received.append(
                {
                    "message": message,
                    "peer": [addr[0], addr[1]],
                }
            )

            if index < len(reply_payloads) and reply_payloads[index] is not None:
                sock.sendto(reply_payloads[index].encode(), addr)
                replies.append(
                    {
                        "message": reply_payloads[index],
                        "peer": [addr[0], addr[1]],
                    }
                )

    _emit({"received": received, "replies": replies})


def send_many_recv(config):
    payloads = config["payloads"]
    recv_count = config["recv_count"]
    replies = []
    delay_ms = config.get("delay_ms", 0)

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        for payload in payloads:
            sock.sendto(
                payload.encode(), (config["target_addr"], config["target_port"])
            )
            if delay_ms:
                import time

                time.sleep(delay_ms / 1000.0)

        while len(replies) < recv_count:
            data, addr = sock.recvfrom(2048)
            replies.append(
                {
                    "message": data.decode(),
                    "peer": [addr[0], addr[1]],
                }
            )

    _emit({"sent": payloads, "replies": replies})


def multi_server(config):
    received = []
    target_count = config["count"]
    ack_prefix = config.get("ack_prefix", "ack:")

    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        while len(received) < target_count:
            data, addr = sock.recvfrom(2048)
            message = data.decode()
            received.append(
                {
                    "message": message,
                    "peer": [addr[0], addr[1]],
                }
            )
            sock.sendto(f"{ack_prefix}{message}".encode(), addr)

    _emit({"port": config["bind_port"], "received": received})


def multi_client(config):
    channels = config["channels"]
    bind_addr = config["bind_addr"]
    bind_ports = config["bind_ports"]
    clients = {}
    replies = []

    for port in bind_ports:
        clients[port] = _socket(bind_addr, port)

    try:
        for channel in channels:
            clients[channel["src_port"]].sendto(
                channel["message"].encode(),
                (channel["dst_addr"], channel["dst_port"]),
            )

        while len(replies) < len(channels):
            ready, _, _ = select.select(list(clients.values()), [], [], TIMEOUT_SEC)
            if not ready:
                raise TimeoutError("timed out waiting for multi-channel replies")

            for sock in ready:
                data, addr = sock.recvfrom(2048)
                replies.append(
                    {
                        "local_port": sock.getsockname()[1],
                        "message": data.decode(),
                        "peer": [addr[0], addr[1]],
                    }
                )
    finally:
        for sock in clients.values():
            sock.close()

    _emit({"channels": channels, "replies": replies})


def simultaneous_exchange(config):
    with _socket(config["bind_addr"], config["bind_port"]) as sock:
        sock.sendto(
            config["payload"].encode(),
            (config["target_addr"], config["target_port"]),
        )
        data, addr = sock.recvfrom(2048)
        _emit(
            {
                "sent": config["payload"],
                "received": data.decode(),
                "peer": [addr[0], addr[1]],
            }
        )


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_flags_expr(expr):
    value = 0
    for name in expr.split("|"):
        flag = name.strip().lower()
        if not flag:
            continue
        value |= {
            "fin": 0x01,
            "syn": 0x02,
            "rst": 0x04,
            "psh": 0x08,
            "ack": 0x10,
            "urg": 0x20,
        }[flag]
    return value


def send_tcp_packet(config):
    import struct

    src_addr = config["bind_addr"]
    dst_addr = config["target_addr"]
    src_port = config["bind_port"]
    dst_port = config["target_port"]
    seq = config.get("seq", 12345)
    ack = config.get("ack", 0)
    payload = config.get("payload", b"")
    if isinstance(payload, str):
        payload = payload.encode()

    flags = _tcp_flags_expr(config["flags"])
    window = socket.htons(config.get("window", 5840))
    doff = 5

    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        doff << 4,
        flags,
        window,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_addr),
        socket.inet_aton(dst_addr),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload),
    )
    tcp_check = _checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        doff << 4,
        flags,
        window,
        tcp_check,
        0,
    )

    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        total_len,
        config.get("ip_id", 0),
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(src_addr),
        socket.inet_aton(dst_addr),
    )
    ip_check = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,
        0,
        total_len,
        config.get("ip_id", 0),
        0,
        64,
        socket.IPPROTO_TCP,
        ip_check,
        socket.inet_aton(src_addr),
        socket.inet_aton(dst_addr),
    )

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw_sock:
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_sock.sendto(ip_header + tcp_header + payload, (dst_addr, 0))

    _emit({"done": True})


def capture_tcp_packet(config):
    src_addr = config["bind_addr"]
    dst_addr = config["target_addr"]
    src_port = config["bind_port"]
    dst_port = config["target_port"]
    expected_payload = config.get("payload")
    if isinstance(expected_payload, str):
        expected_payload = expected_payload.encode()

    with socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800)
    ) as raw_sock:
        raw_sock.settimeout(config.get("timeout_sec", TIMEOUT_SEC))

        while True:
            frame, _ = raw_sock.recvfrom(65535)
            if len(frame) < 14 + 20 + 20:
                continue
            if struct.unpack("!H", frame[12:14])[0] != 0x0800:
                continue

            ip_offset = 14
            version_ihl = frame[ip_offset]
            if version_ihl >> 4 != 4:
                continue
            ihl = (version_ihl & 0x0F) * 4
            if frame[ip_offset + 9] != socket.IPPROTO_TCP:
                continue

            packet_src_addr = socket.inet_ntoa(frame[ip_offset + 12 : ip_offset + 16])
            packet_dst_addr = socket.inet_ntoa(frame[ip_offset + 16 : ip_offset + 20])
            if packet_src_addr != src_addr or packet_dst_addr != dst_addr:
                continue

            total_len = struct.unpack("!H", frame[ip_offset + 2 : ip_offset + 4])[0]
            tcp_offset = ip_offset + ihl
            tcp_header = frame[tcp_offset : tcp_offset + 20]
            if len(tcp_header) < 20:
                continue

            (
                packet_src_port,
                packet_dst_port,
                seq,
                ack,
                data_offset,
                flags,
                _,
                _,
                _,
            ) = struct.unpack("!HHLLBBHHH", tcp_header)
            if packet_src_port != src_port or packet_dst_port != dst_port:
                continue

            tcp_header_len = (data_offset >> 4) * 4
            payload_start = tcp_offset + tcp_header_len
            payload_end = ip_offset + total_len
            payload = frame[payload_start:payload_end]
            if expected_payload is not None and payload != expected_payload:
                continue

            _emit(
                {
                    "seq": seq,
                    "ack": ack,
                    "flags": flags,
                    "payload": payload.decode(errors="ignore"),
                }
            )
            return


SCENARIOS = {
    "ping_server": ping_server,
    "ping_client": ping_client,
    "echo_server": echo_server,
    "echo_client": echo_client,
    "recv_many": recv_many,
    "send_many": send_many,
    "simultaneous_exchange": simultaneous_exchange,
    "send_tcp_packet": send_tcp_packet,
    "capture_tcp_packet": capture_tcp_packet,
    "recv_many_reply": recv_many_reply,
    "send_many_recv": send_many_recv,
    "multi_server": multi_server,
    "multi_client": multi_client,
}


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: scenarios.py <scenario> <json-config>")

    scenario = argv[1]
    config = json.loads(argv[2])
    handler = SCENARIOS.get(scenario)
    if handler is None:
        raise SystemExit(f"unknown scenario: {scenario}")

    handler(config)


if __name__ == "__main__":
    main(sys.argv)
