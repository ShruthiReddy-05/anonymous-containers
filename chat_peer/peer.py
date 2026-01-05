import argparse
import asyncio
import base64
import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import docker
import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


DEFAULT_TTL_SECONDS = int(os.getenv("TTL_SECONDS", "600"))
DEFAULT_SERVER_URL = os.getenv("CHAT_SERVER_URL", "ws://chat_server:5000/ws")


@dataclass
class EncryptionBundle:
    ciphertext: str
    envelopes: Dict[str, str]


class PeerState:
    def __init__(self, username: str, private_key: rsa.RSAPrivateKey) -> None:
        self.username = username
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._peer_public_keys: Dict[str, rsa.RSAPublicKey] = {}
        self._peer_fingerprints: Dict[str, str] = {}
        self._peers: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        return self._private_key

    def public_key_pem(self) -> str:
        return (
            self._public_key
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

    async def set_peers(self, peers: Iterable[str]) -> None:
        async with self._lock:
            self._peers = {peer for peer in peers if peer != self.username}

    async def add_peer(self, peer: str) -> None:
        if peer == self.username:
            return
        async with self._lock:
            self._peers.add(peer)

    async def remove_peer(self, peer: str) -> None:
        async with self._lock:
            self._peers.discard(peer)
            self._peer_public_keys.pop(peer, None)
            self._peer_fingerprints.pop(peer, None)

    async def store_peer_public_key(self, peer: str, pem: str) -> Optional[str]:
        if peer == self.username:
            return None
        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        except ValueError:
            return None

        fingerprint = self._fingerprint_key(public_key)
        async with self._lock:
            self._peer_public_keys[peer] = public_key
            self._peer_fingerprints[peer] = fingerprint
            self._peers.add(peer)
        return fingerprint

    async def peer_fingerprint(self, peer: str) -> Optional[str]:
        async with self._lock:
            return self._peer_fingerprints.get(peer)

    async def list_peers(self) -> Dict[str, Optional[str]]:
        async with self._lock:
            return {
                peer: self._peer_fingerprints.get(peer)
                for peer in sorted(self._peers)
            }

    async def resolve_recipients(self, targets: Optional[Iterable[str]] = None) -> Dict[str, rsa.RSAPublicKey]:
        async with self._lock:
            if targets:
                resolved = {
                    peer: self._peer_public_keys[peer]
                    for peer in targets
                    if peer in self._peer_public_keys
                }
            else:
                resolved = dict(self._peer_public_keys)
        resolved.pop(self.username, None)
        return resolved

    def decrypt_envelope(self, envelope_b64: str) -> Optional[bytes]:
        try:
            encrypted_key = base64.b64decode(envelope_b64)
            session_key = self._private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return session_key
        except Exception:
            return None

    @staticmethod
    def _fingerprint_key(public_key: rsa.RSAPublicKey) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return digest.finalize().hex()[:32]


class SelfDestructTimer:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = ttl_seconds
        self._started_at = time.time()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._worker, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def remaining(self) -> int:
        elapsed = time.time() - self._started_at
        remaining = int(self.ttl_seconds - elapsed)
        return max(0, remaining)

    def _worker(self) -> None:
        milestones = {self.ttl_seconds, 300, 180, 120, 60, 30, 10, 5, 3, 2, 1}
        milestones = {m for m in milestones if m > 0}
        warned = set()
        try:
            while not self._stop_event.is_set():
                remaining = self.remaining()
                if remaining <= 0:
                    print("[timer] Self-destruct sequence initiated", flush=True)
                    self._delete_container()
                    break

                if remaining in milestones and remaining not in warned:
                    warned.add(remaining)
                    mins, secs = divmod(remaining, 60)
                    if mins:
                        print(
                            f"[timer] {mins} minute(s) {secs} second(s) remaining",
                            flush=True,
                        )
                    else:
                        print(f"[timer] {secs} second(s) remaining", flush=True)

                time.sleep(1)
        finally:
            self._stop_event.set()

    def _delete_container(self) -> None:
        hostname = socket.gethostname()
        try:
            client = docker.from_env()
            container = client.containers.get(hostname)
            print("[timer] Destroying container", flush=True)
            container.remove(force=True)
        except Exception as exc:
            print(f"[timer] Failed to remove container: {exc}", flush=True)
        finally:
            os._exit(0)


def generate_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def encrypt_message(message: str, recipients: Dict[str, rsa.RSAPublicKey]) -> EncryptionBundle:
    if not recipients:
        raise ValueError("no recipients with known public keys")

    session_key = Fernet.generate_key()
    fernet = Fernet(session_key)
    ciphertext = fernet.encrypt(message.encode("utf-8")).decode("utf-8")

    envelopes: Dict[str, str] = {}
    for peer, public_key in recipients.items():
        encrypted_session_key = public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        envelopes[peer] = base64.b64encode(encrypted_session_key).decode("utf-8")

    return EncryptionBundle(ciphertext=ciphertext, envelopes=envelopes)


async def transmitter(websocket: websockets.WebSocketClientProtocol, queue: "asyncio.Queue[str]") -> None:
    try:
        while True:
            payload = await queue.get()
            if payload is None:
                break
            await websocket.send(payload)
    finally:
        await websocket.close()


async def receiver(
    websocket: websockets.WebSocketClientProtocol,
    state: PeerState,
    handshake_event: asyncio.Event,
    registration_result: "asyncio.Future[bool]",
    outgoing: "asyncio.Queue[str]",
) -> None:
    try:
        async for raw in websocket:
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                continue

            msg_type = message.get("type")

            if msg_type == "welcome":
                peers = message.get("peers", [])
                await state.set_peers(peers)
                if not registration_result.done():
                    registration_result.set_result(True)
                handshake_event.set()
                print(
                    "[system] Connected to relay. Known peers: "
                    + (", ".join(peers) if peers else "(none yet)"),
                    flush=True,
                )
                await outgoing.put(
                    json.dumps(
                        {
                            "type": "public_key",
                            "from": state.username,
                            "public_key": state.public_key_pem(),
                        }
                    )
                )

            elif msg_type == "error":
                reason = message.get("message", "unknown-error")
                print(f"[error] {reason}", flush=True)
                if not registration_result.done():
                    registration_result.set_result(False)
                return

            elif msg_type == "system":
                content = message.get("message", "")
                print(f"[system] {content}", flush=True)
                if content.endswith("joined"):
                    peer = content[:-6].strip()
                    await state.add_peer(peer)
                    # Re-broadcast our public key so newcomers can chat with us
                    await outgoing.put(
                        json.dumps(
                            {
                                "type": "public_key",
                                "from": state.username,
                                "public_key": state.public_key_pem(),
                            }
                        )
                    )
                elif content.endswith("left"):
                    peer = content[:-4].strip()
                    await state.remove_peer(peer)

            elif msg_type == "public_key":
                peer = message.get("from")
                pem = message.get("public_key")
                if not peer or not pem:
                    continue
                fingerprint = await state.store_peer_public_key(peer, pem)
                if fingerprint:
                    print(
                        f"[key] Received key for {peer} (fingerprint {fingerprint})",
                        flush=True,
                    )

            elif msg_type == "chat":
                sender = message.get("from") or "unknown"
                key_envelopes = message.get("key_envelopes", {})
                ciphertext = message.get("ciphertext")
                if not ciphertext or not isinstance(key_envelopes, dict):
                    continue

                envelope = key_envelopes.get(state.username)
                if not envelope:
                    continue

                session_key = state.decrypt_envelope(envelope)
                if not session_key:
                    continue

                try:
                    plaintext = Fernet(session_key).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
                except Exception:
                    continue

                print(f"{sender} › {plaintext}", flush=True)

            else:
                continue
    finally:
        if not registration_result.done():
            registration_result.set_result(False)
        handshake_event.set()


async def cli_loop(
    state: PeerState,
    handshake_event: asyncio.Event,
    outgoing: "asyncio.Queue[str]",
    timer: SelfDestructTimer,
) -> None:
    await handshake_event.wait()
    print("[help] Use '@user1,@user2 message' to target peers. /peers, /ttl, /quit.", flush=True)

    while True:
        try:
            user_input = await asyncio.to_thread(input, f"{state.username}> ")
        except (EOFError, KeyboardInterrupt):
            print("[cli] Input interrupted", flush=True)
            break

        text = user_input.strip()
        if not text:
            continue

        if text == "/quit":
            break
        if text == "/peers":
            peers = await state.list_peers()
            if not peers:
                print("[cli] No peers connected", flush=True)
            else:
                for peer, fingerprint in peers.items():
                    fingerprint_display = fingerprint or "(no key yet)"
                    print(f"[cli] {peer}: {fingerprint_display}", flush=True)
            continue
        if text == "/ttl":
            remaining = timer.remaining()
            mins, secs = divmod(remaining, 60)
            print(f"[cli] Container expires in {mins}m{secs:02d}s", flush=True)
            continue
        if text.startswith("/help"):
            print("[help] '@user message' sends to user. '/peers', '/ttl', '/quit'.", flush=True)
            continue

        targets: Optional[Iterable[str]] = None
        message_text = text
        if text.startswith("@"):
            if " " not in text:
                print("[cli] Usage: @user1,@user2 message", flush=True)
                continue
            target_chunk, message_text = text.split(" ", 1)
            targets = [peer.strip("@ ") for peer in target_chunk.split(",") if peer]
            if not message_text.strip():
                print("[cli] Message text required", flush=True)
                continue

        recipients = await state.resolve_recipients(targets)
        if not recipients:
            print("[cli] No recipients with known keys", flush=True)
            continue

        try:
            bundle = encrypt_message(message_text, recipients)
        except ValueError:
            print("[cli] Unable to encrypt message", flush=True)
            continue

        payload = {
            "type": "chat",
            "from": state.username,
            "ciphertext": bundle.ciphertext,
            "key_envelopes": bundle.envelopes,
            "recipients": list(recipients.keys()),
            "timestamp": time.time(),
        }
        await outgoing.put(json.dumps(payload))
        print("[cli] Encrypted message dispatched", flush=True)

    await outgoing.put(json.dumps({"type": "system", "message": f"{state.username} disconnecting"}))
    await outgoing.put(None)


async def run_client(args: argparse.Namespace, timer: SelfDestructTimer) -> int:
    private_key = generate_keypair()
    state = PeerState(args.username, private_key)

    uri = args.connect
    print(f"[init] Connecting to {uri} as {args.username}", flush=True)

    try:
        async with websockets.connect(uri, ping_interval=20, ping_timeout=20) as websocket:
            await websocket.send(json.dumps({"type": "register", "username": args.username}))

            registration_result: "asyncio.Future[bool]" = asyncio.get_running_loop().create_future()
            handshake_event = asyncio.Event()
            outgoing: "asyncio.Queue[str]" = asyncio.Queue()

            recv_task = asyncio.create_task(
                receiver(websocket, state, handshake_event, registration_result, outgoing)
            )
            send_task = asyncio.create_task(transmitter(websocket, outgoing))
            cli_task = asyncio.create_task(cli_loop(state, handshake_event, outgoing, timer))

            success = await registration_result
            if not success:
                recv_task.cancel()
                cli_task.cancel()
                await outgoing.put(None)
                await asyncio.gather(recv_task, send_task, cli_task, return_exceptions=True)
                return 1

            await asyncio.gather(recv_task, send_task, cli_task, return_exceptions=True)
            return 0
    except ConnectionRefusedError:
        print("[error] Unable to reach relay server", flush=True)
        return 1
    except websockets.InvalidStatusCode as exc:
        print(f"[error] WebSocket rejected connection: {exc.status_code}", flush=True)
        return 1
    except Exception as exc:
        print(f"[error] Unexpected failure: {exc}", flush=True)
        return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymous Containers secure peer client")
    parser.add_argument(
        "--username",
        default=os.getenv("USERNAME"),
        required=os.getenv("USERNAME") is None,
        help="Display name for this peer",
    )
    parser.add_argument(
        "--connect",
        default=DEFAULT_SERVER_URL,
        help="WebSocket URL of the relay server",
    )
    parser.add_argument(
        "--ttl",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help="Time-to-live in seconds before self-destruct",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timer = SelfDestructTimer(args.ttl)
    timer.start()

    try:
        exit_code = asyncio.run(run_client(args, timer))
    finally:
        timer.stop()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
