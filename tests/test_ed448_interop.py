"""
Interoperability checks for Ed448 keys against AsyncSSH.
"""

import asyncio
import threading

import pytest

from paramiko import AutoAddPolicy, Ed448Key, Message, PKey, SSHClient

from ._util import _support

asyncssh = pytest.importorskip("asyncssh")
CERT_TYPE_USER = asyncssh.public_key.CERT_TYPE_USER


def _load_asyncssh_key():
    with open(_support("ed448.key"), "rb") as fd:
        return asyncssh.import_private_key(fd.read())


def test_paramiko_signature_verifies_in_asyncssh():
    key = Ed448Key.from_private_key_file(_support("ed448.key"))
    async_key = _load_asyncssh_key()
    public_key = asyncssh.import_public_key(
        async_key.export_public_key("openssh").decode()
    )
    data = b"ice weasels"
    signature = key.sign_ssh_data(data).asbytes()
    assert public_key.verify(data, signature)


def test_asyncssh_signature_verifies_in_paramiko():
    key = Ed448Key.from_private_key_file(_support("ed448.key"))
    async_key = _load_asyncssh_key()
    data = b"ice weasels"
    signature = async_key.sign(data, b"ssh-ed448")
    msg = Message(signature)
    assert key.verify_ssh_sig(data, msg)


def test_asyncssh_openssh_private_key_loads_in_paramiko(tmp_path):
    async_key = asyncssh.generate_private_key("ssh-ed448")
    path = tmp_path / "ed448.key"
    path.write_bytes(async_key.export_private_key("openssh"))
    key = PKey.from_path(path)
    assert isinstance(key, Ed448Key)
    assert key.asbytes() == async_key.public_data
    signature = key.sign_ssh_data(b"ice weasels").asbytes()
    public_key = asyncssh.import_public_key(
        async_key.export_public_key("openssh").decode()
    )
    assert public_key.verify(b"ice weasels", signature)


def test_certificate_interoperates_with_asyncssh():
    key = Ed448Key.from_private_key_file(_support("ed448.key"))
    key.load_certificate(_support("ed448.key-cert.pub"))
    with open(_support("ed448.key-cert.pub")) as fd:
        cert = asyncssh.import_certificate(fd.read())
    assert key.public_blob.key_type == cert.algorithm.decode()
    assert key.public_blob.key_blob == cert.public_data
    cert.validate(CERT_TYPE_USER, "user1")


def test_paramiko_client_authenticates_to_asyncssh_with_ed448(tmp_path):
    host_key = asyncssh.generate_private_key("ssh-ed448")
    user_key = _load_asyncssh_key()
    with open(_support("rsa.key"), "rb") as fd:
        ca_key = asyncssh.import_private_key(fd.read())
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_text(
        user_key.export_public_key("openssh").decode()
        + "\n"
        + "cert-authority "
        + ca_key.export_public_key("openssh").decode()
        + "\n"
    )
    ready = threading.Event()
    stop = threading.Event()
    errors = []
    state = {}

    def run_server():
        async def handle_client(process):
            process.exit(0)

        async def main():
            server = await asyncssh.listen(
                "127.0.0.1",
                0,
                server_host_keys=[host_key],
                authorized_client_keys=str(authorized_keys),
                process_factory=handle_client,
            )
            state["server"] = server
            state["port"] = server.get_port()
            ready.set()
            while not stop.is_set():
                await asyncio.sleep(0.05)
            server.close()

        try:
            asyncio.run(main())
        except BaseException as e:
            errors.append(e)
            ready.set()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    try:
        assert ready.wait(10)
        if errors:
            raise errors[0]
        for use_cert in (False, True):
            key = Ed448Key.from_private_key_file(_support("ed448.key"))
            if use_cert:
                key.load_certificate(_support("ed448.key-cert.pub"))
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            try:
                client.connect(
                    "127.0.0.1",
                    port=state["port"],
                    username="user1",
                    pkey=key,
                    look_for_keys=False,
                    allow_agent=False,
                )
                assert (
                    client.get_transport().get_remote_server_key().get_name()
                    == "ssh-ed448"
                )
            finally:
                client.close()
    finally:
        stop.set()
        thread.join(5)
        assert not thread.is_alive()
