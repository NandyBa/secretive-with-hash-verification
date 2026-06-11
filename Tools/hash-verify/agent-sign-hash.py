#!/usr/bin/env python3
"""
Transparent SSH-agent proxy that prints the SHA-256 of the exact bytes the agent
is asked to sign — the same bytes Secretive's Touch ID prompt now displays.

Why a proxy: git and ssh-keygen build the SSHSIG blob internally and send it
straight to the agent over $SSH_AUTH_SOCK. They never expose that buffer on
stdout, so the only fully reliable place to observe the exact bytes is on the
wire between the SSH client and the agent. This proxy sits in the middle,
forwards every byte untouched, and for each SSH_AGENTC_SIGN_REQUEST (type 13)
prints the SHA-256 of the `data` field — i.e. exactly what Secretive hashes.

Usage:
    1. Start the proxy (point it at Secretive's real socket):
         ./agent-sign-hash.py "$SSH_AUTH_SOCK"
       It prints a line like:
         export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock

    2. In ANOTHER terminal, export that and run your signed commit:
         export SSH_AUTH_SOCK=/tmp/secretive-hash-proxy.sock
         git commit -S -m "test"

    3. Approve the Touch ID prompt. Compare the SHA-256 printed by the proxy
       with the "SHA-256:" line in the prompt. They must be identical.

No third-party dependencies; standard library only.
"""

import hashlib
import os
import socket
import struct
import sys
import threading

DEFAULT_PROXY_PATH = "/tmp/secretive-hash-proxy.sock"

SSH_AGENTC_SIGN_REQUEST = 13


def parse_string(buf, offset):
    """Read an SSH 'string' (uint32 big-endian length + bytes). Returns (bytes, new_offset) or None."""
    if offset + 4 > len(buf):
        return None
    (length,) = struct.unpack(">I", buf[offset:offset + 4])
    offset += 4
    if offset + length > len(buf):
        return None
    return buf[offset:offset + length], offset + length


def inspect_sign_request(message_body):
    """message_body is the payload AFTER the 1-byte type. For a sign request:
       string key_blob, string data, uint32 flags. We hash `data`."""
    parsed = parse_string(message_body, 0)
    if parsed is None:
        return
    _key_blob, offset = parsed
    parsed = parse_string(message_body, offset)
    if parsed is None:
        return
    data, _ = parsed
    digest = hashlib.sha256(data).hexdigest()
    print(f"\n[sign] {len(data)} bytes to sign", file=sys.stderr)
    if data[:6] == b"SSHSIG":
        ns = parse_string(data, 6)
        if ns is not None:
            namespace, off = ns
            reserved = parse_string(data, off)
            if reserved is not None:
                _, off = reserved
                algo = parse_string(data, off)
                algo_str = algo[0].decode("utf-8", "replace") if algo else "?"
                print(f"[sign] SSHSIG namespace=\"{namespace.decode('utf-8','replace')}\" "
                      f"hash={algo_str}", file=sys.stderr)
    print(f"[sign] SHA-256: {digest}", file=sys.stderr)
    print("[sign] ^ compare this with the SHA-256 in Secretive's Touch ID prompt\n", file=sys.stderr)


def pump_client_to_agent(client, agent):
    """Forward client->agent, parsing complete agent messages to inspect sign requests."""
    buffer = b""
    try:
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            agent.sendall(chunk)  # forward untouched
            buffer += chunk
            # Parse as many complete messages as are buffered.
            while len(buffer) >= 4:
                (msg_len,) = struct.unpack(">I", buffer[:4])
                if len(buffer) < 4 + msg_len:
                    break
                message = buffer[4:4 + msg_len]
                buffer = buffer[4 + msg_len:]
                if message and message[0] == SSH_AGENTC_SIGN_REQUEST:
                    inspect_sign_request(message[1:])
    except OSError:
        pass
    finally:
        try:
            agent.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def pump_agent_to_client(agent, client):
    try:
        while True:
            chunk = agent.recv(65536)
            if not chunk:
                break
            client.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, real_agent_path):
    try:
        agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent.connect(real_agent_path)
    except OSError as exc:
        print(f"error: cannot connect to real agent at {real_agent_path}: {exc}", file=sys.stderr)
        client.close()
        return
    t1 = threading.Thread(target=pump_client_to_agent, args=(client, agent), daemon=True)
    t2 = threading.Thread(target=pump_agent_to_client, args=(agent, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    agent.close()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print(f"\nUsage: {sys.argv[0]} <real-agent-socket> [proxy-socket-path]", file=sys.stderr)
        sys.exit(2)
    real_agent_path = sys.argv[1]
    proxy_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PROXY_PATH

    if not os.path.exists(real_agent_path):
        print(f"error: real agent socket not found: {real_agent_path}", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(proxy_path):
        os.unlink(proxy_path)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(proxy_path)
    listener.listen(64)

    print(f"Proxying {proxy_path} -> {real_agent_path}", file=sys.stderr)
    print(f"export SSH_AUTH_SOCK={proxy_path}")
    sys.stdout.flush()

    try:
        while True:
            client, _ = listener.accept()
            threading.Thread(target=handle, args=(client, real_agent_path), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        if os.path.exists(proxy_path):
            os.unlink(proxy_path)


if __name__ == "__main__":
    main()
