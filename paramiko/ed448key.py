# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Ed448 keys.
"""

from io import StringIO

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448

from paramiko.message import Message
from paramiko.pkey import PEM, PKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException


class Ed448Key(PKey):
    """
    Representation of an `Ed448 <https://ed448goldilocks.org/>`_ key.

    Ed448 keys and certificates use the ``ssh-ed448`` and
    ``ssh-ed448-cert-v01@openssh.com`` identifiers defined by :rfc:`8709`.

    .. versionadded:: 5.2
    """

    name = "ssh-ed448"
    _cert_name = "ssh-ed448-cert-v01@openssh.com"
    _key_size = 57
    _signature_size = 114

    @staticmethod
    def _pkcs8_pem():
        return PEM._replace(format=serialization.PrivateFormat.PKCS8)

    def __init__(
        self,
        msg=None,
        data=None,
        filename=None,
        password=None,
        file_obj=None,
        vals=None,
    ):
        self.public_blob = None
        self._signing_key = None
        self._verifying_key = None
        if msg is None and data is not None:
            msg = Message(data)
        if msg is not None:
            self._check_type_and_load_cert(
                msg=msg,
                key_type=self.name,
                cert_type=self._cert_name,
            )
            key_data = msg.get_binary()
            if len(key_data) != self._key_size:
                raise SSHException("Invalid Ed448 public key")
            try:
                self._verifying_key = ed448.Ed448PublicKey.from_public_bytes(
                    key_data
                )
            except ValueError:
                raise SSHException("Invalid Ed448 public key")
        elif vals is not None:
            self._signing_key = vals
            self._verifying_key = vals.public_key()
        elif filename is not None:
            with open(filename, "rb") as f:
                data = f.read()
            self._load_private_key(data, password)
        elif file_obj is not None:
            data = file_obj.read()
            if isinstance(data, str):
                data = data.encode("ascii")
            self._load_private_key(data, password)

        if self._signing_key is None and self._verifying_key is None:
            raise ValueError("need a key")

    def _load_private_key(self, data, password):
        if b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
            text = StringIO(data.decode("ascii"))
            _, key_data = self._read_private_key(
                "ED448", text, password=password
            )
            self._signing_key = self._decode_openssh_private_key(key_data)
        else:
            try:
                key = serialization.load_pem_private_key(
                    data, password=password
                )
            except TypeError as e:
                if password is None:
                    raise PasswordRequiredException(
                        "Private key file is encrypted"
                    )
                raise SSHException(str(e))
            except (ValueError, UnsupportedAlgorithm) as e:
                raise SSHException(str(e))
            if not isinstance(key, ed448.Ed448PrivateKey):
                raise SSHException("Invalid Ed448 private key")
            self._signing_key = key
        self._verifying_key = self._signing_key.public_key()

    def _decode_openssh_private_key(self, data):
        message = Message(data)
        public = message.get_binary()
        key_data = message.get_binary()
        if len(public) != self._key_size:
            raise SSHException("Invalid key")
        if len(key_data) != self._key_size * 2:
            raise SSHException("Invalid key")
        if key_data[self._key_size :] != public:
            raise SSHException("Invalid key")
        try:
            key = ed448.Ed448PrivateKey.from_private_bytes(
                key_data[: self._key_size]
            )
        except ValueError:
            raise SSHException("Invalid key")
        if (
            key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            != public
        ):
            raise SSHException("Invalid key")
        # Comment follows the private/public key material and is irrelevant.
        message.get_binary()
        return key

    def asbytes(self):
        key = self._verifying_key
        key_bytes = (
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if key is not None
            else b""
        )
        m = Message()
        m.add_string(self.name)
        m.add_string(key_bytes)
        return m.asbytes()

    @property
    def _fields(self):
        key = self.verifying_key
        key_bytes = (
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if key is not None
            else b""
        )
        return (self.get_name(), key_bytes)

    # TODO (backwards incompat): remove
    def get_name(self):
        return self.name

    def get_bits(self):
        return 448

    def can_sign(self):
        return self._signing_key is not None

    def can_verify(self):
        return self._verifying_key is not None

    @property
    def private_key(self):
        return self._signing_key

    @property
    def verifying_key(self):
        if self._verifying_key is not None:
            return self._verifying_key
        if self._signing_key is not None:
            return self._signing_key.public_key()
        return None

    def sign_ssh_data(self, data, algorithm=None):
        message = Message()
        message.add_string(self.name)
        message.add_string(self._signing_key.sign(data))
        return message

    def write_private_key_file(
        self, filename, password=None, file_format=None
    ):
        if file_format is None or file_format == PEM:
            file_format = self._pkcs8_pem()
        super().write_private_key_file(filename, password, file_format)

    def write_private_key(self, file_obj, password=None, file_format=None):
        if file_format is None or file_format == PEM:
            file_format = self._pkcs8_pem()
        super().write_private_key(file_obj, password, file_format)

    def verify_ssh_sig(self, data, msg):
        if msg.get_text() != self.name:
            return False
        signature = msg.get_binary()
        if len(signature) != self._signature_size:
            return False
        try:
            self.verifying_key.verify(signature, data)
        except InvalidSignature:
            return False
        return True

    @classmethod
    def generate(cls, progress_func=None):
        """
        Generate a new private Ed448 key.

        :param progress_func: Not used for this type of key.
        :returns: A new private key (`.Ed448Key`) object.
        """
        return cls(vals=ed448.Ed448PrivateKey.generate())
