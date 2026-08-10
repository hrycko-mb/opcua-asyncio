from __future__ import annotations

import logging
import struct
import sys
import time
from abc import ABCMeta, abstractmethod
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Generic, TypeVar
from warnings import deprecated

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from ..crypto import uacrypto
from ..ua import MessageSecurityMode, SecurityPolicyType, UaError

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override

if TYPE_CHECKING:
    from ..crypto.permission_rules import PermissionRuleset


_logger = logging.getLogger(__name__)


class Signer:
    """
    Abstract base class for cryptographic signature algorithm
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def signature_size(self) -> int:
        pass

    @abstractmethod
    def signature(self, data: bytes) -> bytes:
        pass


class Verifier:
    """
    Abstract base class for cryptographic signature verification
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def signature_size(self) -> int:
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes) -> None:
        pass

    def reset(self) -> None:
        attrs = self.__dict__
        for k in attrs:
            attrs[k] = None


class Encryptor:
    """
    Abstract base class for encryption algorithm
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def plain_block_size(self) -> int:
        pass

    @abstractmethod
    def encrypted_block_size(self) -> int:
        pass

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass


class Decryptor:
    """
    Abstract base class for decryption algorithm
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def plain_block_size(self) -> int:
        pass

    @abstractmethod
    def encrypted_block_size(self) -> int:
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        pass

    def reset(self) -> None:
        attrs = self.__dict__
        for k in attrs:
            attrs[k] = None


class CryptographyNone:
    """
    Base class for symmetric/asymmetric cryptography
    """

    def __init__(self) -> None:
        pass

    def plain_block_size(self) -> int:
        """
        Size of plain text block for block cipher.
        """
        return 1

    def encrypted_block_size(self) -> int:
        """
        Size of encrypted text block for block cipher.
        """
        return 1

    def padding(self, size: int) -> bytes:
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        return b""

    def min_padding_size(self) -> int:
        return 0

    def signature_size(self) -> int:
        return 0

    def signature(self, data: bytes) -> bytes:
        return b""

    def encrypt(self, data: bytes) -> bytes:
        return data

    def decrypt(self, data: bytes) -> bytes:
        return data

    def vsignature_size(self) -> int:
        return 0

    def verify(self, data: bytes, signature: bytes) -> None:
        """
        Verify signature and raise exception if signature is invalid
        """

    def remove_padding(self, data: bytes) -> bytes:
        return data


class Cryptography(CryptographyNone):
    """
    Security policy: Sign or SignAndEncrypt
    """

    def __init__(self, mode: MessageSecurityMode = MessageSecurityMode.Sign) -> None:
        self.signer: Signer | None = None
        self.verifier: Verifier | None = None
        self.prev_verifier: Verifier | None = None
        self.encryptor: Encryptor | None = None
        self.decryptor: Decryptor | None = None
        self.prev_decryptor: Decryptor | None = None
        # we turn this flag on to fallback on previous key
        self._use_prev_key = False
        self.key_expiration = 0.0
        self.prev_key_expiration = 0.0
        if mode not in (MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt):
            raise ValueError(f"unknown security mode {mode}")
        self.is_encrypted = mode == MessageSecurityMode.SignAndEncrypt

    @override
    def plain_block_size(self) -> int:
        """
        Size of plain text block for block cipher.
        """
        if self.is_encrypted and self.encryptor:
            return self.encryptor.plain_block_size()
        return 1

    @override
    def encrypted_block_size(self) -> int:
        """
        Size of encrypted text block for block cipher.
        """
        if self.is_encrypted and self.encryptor:
            return self.encryptor.encrypted_block_size()
        return 1

    @override
    def padding(self, size: int) -> bytes:
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        if not self.is_encrypted or not self.encryptor:
            return b""
        block_size = self.encryptor.plain_block_size()
        extrapad_size = 2 if self.encryptor.encrypted_block_size() > 256 else 1
        rem = (size + self.signature_size() + extrapad_size) % block_size
        if rem != 0:
            rem = block_size - rem
        data = bytes(bytearray([rem % 256])) * (rem + 1)
        if self.encryptor.encrypted_block_size() > 256:
            data += bytes(bytearray([rem >> 8]))
        return data

    @override
    def min_padding_size(self) -> int:
        if self.is_encrypted:
            return 1
        return 0

    @override
    def signature_size(self) -> int:
        if not self.signer:
            raise RuntimeError("Signer was not set")
        return self.signer.signature_size()

    @override
    def signature(self, data: bytes) -> bytes:
        if not self.signer:
            raise RuntimeError("Signer was not set")
        return self.signer.signature(data)

    @override
    def vsignature_size(self) -> int:
        if not self.verifier:
            raise RuntimeError("Verifier was not set")
        return self.verifier.signature_size()

    @override
    def verify(self, data: bytes, sig: bytes) -> None:
        if not self.verifier:
            raise RuntimeError("Verifier was not set")
        if self.use_prev_key and self.prev_verifier:
            _logger.debug("Message verification fallback: trying with previous secure channel key")
            self.prev_verifier.verify(data, sig)
            return
        self.verifier.verify(data, sig)

    @override
    def encrypt(self, data: bytes) -> bytes:
        if not self.encryptor:
            raise RuntimeError("Encryptor was not set")
        if self.is_encrypted:
            if not len(data) % self.encryptor.plain_block_size() == 0:
                raise ValueError
            return self.encryptor.encrypt(data)
        return data

    @override
    def decrypt(self, data: bytes) -> bytes:
        if not self.decryptor:
            raise RuntimeError("Decryptor was not set")
        if self.is_encrypted:
            self.revolved_expired_key()
            if self.use_prev_key and self.prev_decryptor:
                return self.prev_decryptor.decrypt(data)
            return self.decryptor.decrypt(data)
        return data

    def revolved_expired_key(self) -> None:
        """
        Remove expired keys as soon as possible
        """
        now = time.monotonic()
        if now > self.prev_key_expiration:
            if self.prev_decryptor and self.prev_verifier:
                self.prev_decryptor.reset()
                self.prev_decryptor = None
                self.prev_verifier.reset()
                self.prev_verifier = None
                _logger.debug("Expired secure_channel keys removed")

    @property
    def use_prev_key(self) -> bool:
        if self._use_prev_key:
            if self.prev_decryptor and self.prev_verifier:
                return True
            raise uacrypto.InvalidSignature
        return False

    @use_prev_key.setter
    def use_prev_key(self, value: bool) -> None:
        self._use_prev_key = value

    @override
    def remove_padding(self, data: bytes) -> bytes:
        decryptor = self.decryptor if not self.use_prev_key else self.prev_decryptor
        if self.is_encrypted and decryptor:
            if decryptor.encrypted_block_size() > 256:
                pad_size = struct.unpack("<h", data[-2:])[0] + 2
            else:
                pad_size = bytearray(data[-1:])[0] + 1
            return data[:-pad_size]
        return data


def _assert_rsa_priv_key(priv_key: PrivateKeyTypes) -> RSAPrivateKey:
    if not isinstance(priv_key, RSAPrivateKey):
        raise TypeError(f"Expected RSA private key, but {type(priv_key)} was given")
    return priv_key


def _assert_rsa_pub_key(pub_key: PublicKeyTypes) -> RSAPublicKey:
    if not isinstance(pub_key, RSAPublicKey):
        raise TypeError(f"Expected RSA public key, but {type(pub_key)} was given")
    return pub_key


class SignerRsa(Signer):
    def __init__(self, host_privkey: RSAPrivateKey) -> None:
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def signature(self, data: bytes) -> bytes:
        return uacrypto.sign_sha1(self.host_privkey, data)


class VerifierRsa(Verifier):
    def __init__(self, peer_cert: x509.Certificate) -> None:
        self.peer_cert = peer_cert
        self.key_size = _assert_rsa_pub_key(self.peer_cert.public_key()).key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def verify(self, data: bytes, signature: bytes) -> None:
        uacrypto.verify_sha1(self.peer_cert, data, signature)


class EncryptorRsa(Encryptor):
    def __init__(
        self, peer_cert: x509.Certificate, enc_fn: Callable[[RSAPublicKey, bytes], bytes], padding_size: int
    ) -> None:
        self.peer_cert = peer_cert
        self.pub_key = _assert_rsa_pub_key(self.peer_cert.public_key())
        self.key_size = self.pub_key.key_size // 8
        self.encryptor = enc_fn
        self.padding_size = padding_size

    @override
    def plain_block_size(self) -> int:
        return self.key_size - self.padding_size

    @override
    def encrypted_block_size(self) -> int:
        return self.key_size

    @override
    def encrypt(self, data: bytes) -> bytes:

        encrypted = b""
        block_size = self.plain_block_size()
        for i in range(0, len(data), block_size):
            encrypted += self.encryptor(self.pub_key, data[i : i + block_size])
        return encrypted


class DecryptorRsa(Decryptor):
    def __init__(
        self, host_privkey: RSAPrivateKey, dec_fn: Callable[[RSAPrivateKey, bytes], bytes], padding_size: int
    ) -> None:
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8
        self.decryptor = dec_fn
        self.padding_size = padding_size

    @override
    def plain_block_size(self) -> int:
        return self.key_size - self.padding_size

    @override
    def encrypted_block_size(self) -> int:
        return self.key_size

    @override
    def decrypt(self, data: bytes) -> bytes:
        decrypted = b""
        block_size = self.encrypted_block_size()
        for i in range(0, len(data), block_size):
            decrypted += self.decryptor(self.host_privkey, data[i : i + block_size])
        return decrypted


class SignerAesCbc(Signer):
    def __init__(self, key: bytes) -> None:
        self.key = key

    @override
    def signature_size(self) -> int:
        return uacrypto.sha1_size()

    @override
    def signature(self, data: bytes) -> bytes:
        return uacrypto.hmac_sha1(self.key, data)


class VerifierAesCbc(Verifier):
    def __init__(self, key: bytes) -> None:
        self.key = key

    @override
    def signature_size(self) -> int:
        return uacrypto.sha1_size()

    @override
    def verify(self, data: bytes, signature: bytes) -> None:
        expected = uacrypto.hmac_sha1(self.key, data)
        if signature != expected:
            raise uacrypto.InvalidSignature


class EncryptorAesCbc(Encryptor):
    def __init__(self, key: bytes, init_vec: bytes) -> None:
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)

    @override
    def plain_block_size(self) -> int:
        return self.cipher.algorithm.key_size // 8

    @override
    def encrypted_block_size(self) -> int:
        return self.cipher.algorithm.key_size // 8

    @override
    def encrypt(self, data: bytes) -> bytes:
        return uacrypto.cipher_encrypt(self.cipher, data)


class DecryptorAesCbc(Decryptor):
    def __init__(self, key: bytes, init_vec: bytes) -> None:
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)

    @override
    def plain_block_size(self) -> int:
        return self.cipher.algorithm.key_size // 8

    @override
    def encrypted_block_size(self) -> int:
        return self.cipher.algorithm.key_size // 8

    @override
    def decrypt(self, data: bytes) -> bytes:
        return uacrypto.cipher_decrypt(self.cipher, data)


class SignerSha256(Signer):
    def __init__(self, host_privkey: RSAPrivateKey) -> None:
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def signature(self, data: bytes) -> bytes:
        return uacrypto.sign_sha256(self.host_privkey, data)


class VerifierSha256(Verifier):
    def __init__(self, peer_cert: x509.Certificate) -> None:
        self.peer_cert = peer_cert
        self.key_size = _assert_rsa_pub_key(self.peer_cert.public_key()).key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def verify(self, data: bytes, signature: bytes) -> None:
        uacrypto.verify_sha256(self.peer_cert, data, signature)


class SignerHMac256(Signer):
    def __init__(self, key: bytes) -> None:
        self.key = key

    @override
    def signature_size(self) -> int:
        return uacrypto.sha256_size()

    @override
    def signature(self, data: bytes) -> bytes:
        return uacrypto.hmac_sha256(self.key, data)


class VerifierHMac256(Verifier):
    def __init__(self, key: bytes) -> None:
        self.key = key

    @override
    def signature_size(self) -> int:
        return uacrypto.sha256_size()

    @override
    def verify(self, data: bytes, signature: bytes) -> None:
        expected = uacrypto.hmac_sha256(self.key, data)
        if signature != expected:
            raise uacrypto.InvalidSignature


class SignerPssSha256(Signer):
    def __init__(self, host_privkey: RSAPrivateKey) -> None:
        self.host_privkey = host_privkey
        self.key_size = self.host_privkey.key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def signature(self, data: bytes) -> bytes:
        return uacrypto.sign_pss_sha256(self.host_privkey, data)


class VerifierPssSha256(Verifier):
    def __init__(self, peer_cert: x509.Certificate) -> None:
        self.peer_cert = peer_cert
        self.key_size = _assert_rsa_pub_key(self.peer_cert.public_key()).key_size // 8

    @override
    def signature_size(self) -> int:
        return self.key_size

    @override
    def verify(self, data: bytes, signature: bytes) -> None:
        uacrypto.verify_pss_sha256(self.peer_cert, data, signature)


class SecurityPolicy:
    """
    Abstract base class for security policy
    """

    __metaclass__ = ABCMeta

    URI: str
    AsymmetricEncryptionURI: str
    AsymmetricSignatureURI: str
    secure_channel_nonce_length: int
    asymmetric_cryptography: CryptographyNone
    symmetric_cryptography: CryptographyNone
    Mode: MessageSecurityMode
    peer_certificate: bytes | None
    host_certificate: bytes | None
    permissions: PermissionRuleset | None
    host_certificate_chain: Sequence[bytes]

    @abstractmethod
    def __init__(
        self,
        peer_cert: x509.Certificate | None,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey | None,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None,
        host_cert_chain: Sequence[x509.Certificate] | None,
    ) -> None:
        pass

    @abstractmethod
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        pass

    @abstractmethod
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        pass


class SecurityPolicyNone(SecurityPolicy):
    URI = "http://opcfoundation.org/UA/SecurityPolicy#None"
    AsymmetricEncryptionURI: str = ""
    AsymmetricSignatureURI: str = ""
    secure_channel_nonce_length: int = 0

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | None = None,
        host_cert: x509.Certificate | None = None,
        host_privkey: RSAPrivateKey | None = None,
        mode: MessageSecurityMode = MessageSecurityMode.None_,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        self.asymmetric_cryptography = CryptographyNone()
        self.symmetric_cryptography = CryptographyNone()
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        return None

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        return None


class SecurityPolicyAes128Sha256RsaOaep(SecurityPolicy):
    """
    Security Aes128 Sha256 RsaOaep
    A suite of algorithms that uses Sha256 as Key-Wrap-algorithm
    and 128-Bit (16 bytes) for encryption algorithms.

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES128-CBC
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
    - AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
      http://www.w3.org/2001/04/xmlenc#rsa-oaep
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Aes128Sha256RsaOaep_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 16

    @staticmethod
    def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes) -> bytes:
        return uacrypto.encrypt_rsa_oaep(pubkey, data)

    @staticmethod
    def sign_asymmetric(privkey: RSAPrivateKey, data: bytes) -> bytes:
        return uacrypto.sign_sha256(privkey, data)

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | bytes,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography: Cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.signer = SignerSha256(host_privkey)
        self.asymmetric_cryptography.verifier = VerifierSha256(peer_cert)
        self.asymmetric_cryptography.encryptor = EncryptorRsa(peer_cert, uacrypto.encrypt_rsa_oaep, 42)
        self.asymmetric_cryptography.decryptor = DecryptorRsa(host_privkey, uacrypto.decrypt_rsa_oaep, 42)
        self.symmetric_cryptography: Cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        self.symmetric_cryptography.signer = SignerHMac256(sigkey)
        self.symmetric_cryptography.encryptor = EncryptorAesCbc(key, init_vec)

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        if self.symmetric_cryptography.verifier or self.symmetric_cryptography.decryptor:
            self.symmetric_cryptography.prev_verifier = self.symmetric_cryptography.verifier
            self.symmetric_cryptography.prev_decryptor = self.symmetric_cryptography.decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        # lifetime is in ms
        self.symmetric_cryptography.key_expiration = time.monotonic() + (lifetime * 0.001)
        self.symmetric_cryptography.verifier = VerifierHMac256(sigkey)
        self.symmetric_cryptography.decryptor = DecryptorAesCbc(key, init_vec)


class SecurityPolicyAes256Sha256RsaPss(SecurityPolicy):
    """Security policy Aes256_Sha256_RsaPss implementation

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES256-CBC
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
    - AsymmetricSignatureAlgorithm_RSA-PSS-SHA2-256
      http://opcfoundation.org/UA/security/rsa-pss-sha2-256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA2-256
      http://opcfoundation.org/UA/security/rsa-oaep-sha2-256
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Aes256Sha256RsaPss_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
    AsymmetricEncryptionURI = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256"
    AsymmetricSignatureURI = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 32

    @staticmethod
    def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes) -> bytes:
        return uacrypto.encrypt_rsa_oaep_sha256(pubkey, data)

    @staticmethod
    def sign_asymmetric(privkey: RSAPrivateKey, data: bytes) -> bytes:
        return uacrypto.sign_pss_sha256(privkey, data)

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | bytes,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography: Cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.signer = SignerPssSha256(host_privkey)
        self.asymmetric_cryptography.verifier = VerifierPssSha256(peer_cert)
        self.asymmetric_cryptography.encryptor = EncryptorRsa(peer_cert, uacrypto.encrypt_rsa_oaep_sha256, 66)
        self.asymmetric_cryptography.decryptor = DecryptorRsa(host_privkey, uacrypto.decrypt_rsa_oaep_sha256, 66)
        self.symmetric_cryptography: Cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        self.symmetric_cryptography.signer = SignerHMac256(sigkey)
        self.symmetric_cryptography.encryptor = EncryptorAesCbc(key, init_vec)

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        if self.symmetric_cryptography.verifier or self.symmetric_cryptography.decryptor:
            self.symmetric_cryptography.prev_verifier = self.symmetric_cryptography.verifier
            self.symmetric_cryptography.prev_decryptor = self.symmetric_cryptography.decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        # lifetime is in ms
        self.symmetric_cryptography.key_expiration = time.monotonic() + (lifetime * 0.001)
        self.symmetric_cryptography.verifier = VerifierHMac256(sigkey)
        self.symmetric_cryptography.decryptor = DecryptorAesCbc(key, init_vec)


@deprecated("Not a secure policy, use a more secure one.")
class SecurityPolicyBasic128Rsa15(SecurityPolicy):
    """
    DEPRECATED, do not use anymore!

    Security Basic 128Rsa15
    A suite of algorithms that uses RSA15 as Key-Wrap-algorithm
    and 128-Bit (16 bytes) for encryption algorithms.
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes128
      (http://www.w3.org/2001/04/xmlenc#aes128-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - AsymmetricEncryptionAlgorithm - Rsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 128 (16 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger than the certificate shall be rejected.
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
    AsymmetricSignatureURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    secure_channel_nonce_length = 16

    signature_key_size = 16
    symmetric_key_size = 16

    @staticmethod
    def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes) -> bytes:
        return uacrypto.encrypt_rsa15(pubkey, data)

    @staticmethod
    def sign_asymmetric(privkey: RSAPrivateKey, data: bytes) -> bytes:
        return uacrypto.sign_sha1(privkey, data)

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | bytes,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        _logger.warning("DEPRECATED! Do not use SecurityPolicyBasic128Rsa15 anymore!")

        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography: Cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.signer = SignerRsa(host_privkey)
        self.asymmetric_cryptography.verifier = VerifierRsa(peer_cert)
        self.asymmetric_cryptography.encryptor = EncryptorRsa(peer_cert, uacrypto.encrypt_rsa15, 11)
        self.asymmetric_cryptography.decryptor = DecryptorRsa(host_privkey, uacrypto.decrypt_rsa15, 11)
        self.symmetric_cryptography: Cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha1(secret, seed, key_sizes)
        self.symmetric_cryptography.signer = SignerAesCbc(sigkey)
        self.symmetric_cryptography.encryptor = EncryptorAesCbc(key, init_vec)

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha1(secret, seed, key_sizes)
        if self.symmetric_cryptography.verifier or self.symmetric_cryptography.decryptor:
            self.symmetric_cryptography.prev_verifier = self.symmetric_cryptography.verifier
            self.symmetric_cryptography.prev_decryptor = self.symmetric_cryptography.decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        # lifetime is in ms
        self.symmetric_cryptography.key_expiration = time.monotonic() + (lifetime * 0.001)
        self.symmetric_cryptography.verifier = VerifierAesCbc(sigkey)
        self.symmetric_cryptography.decryptor = DecryptorAesCbc(key, init_vec)


@deprecated("Not a secure policy, use a more secure one.")
class SecurityPolicyBasic256(SecurityPolicy):
    """
    DEPRECATED, do not use anymore!

    Security Basic 256
    A suite of algorithms that are for 256-Bit (32 bytes) encryption,
    algorithms include:
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes256
      (http://www.w3.org/2001/04/xmlenc#aes256-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p)
    - AsymmetricEncryptionAlgorithm - RsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 192 (24 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger than the certificate shall be rejected.
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    secure_channel_nonce_length = 32

    signature_key_size = 24
    symmetric_key_size = 32

    @staticmethod
    def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes) -> bytes:
        return uacrypto.encrypt_rsa_oaep(pubkey, data)

    @staticmethod
    def sign_asymmetric(privkey: RSAPrivateKey, data: bytes) -> bytes:
        return uacrypto.sign_sha1(privkey, data)

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | bytes,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        _logger.warning("DEPRECATED! Do not use SecurityPolicyBasic256 anymore!")

        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography: Cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.signer = SignerRsa(host_privkey)
        self.asymmetric_cryptography.verifier = VerifierRsa(peer_cert)
        self.asymmetric_cryptography.encryptor = EncryptorRsa(peer_cert, uacrypto.encrypt_rsa_oaep, 42)
        self.asymmetric_cryptography.decryptor = DecryptorRsa(host_privkey, uacrypto.decrypt_rsa_oaep, 42)
        self.symmetric_cryptography: Cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha1(secret, seed, key_sizes)
        self.symmetric_cryptography.signer = SignerAesCbc(sigkey)
        self.symmetric_cryptography.encryptor = EncryptorAesCbc(key, init_vec)

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha1(secret, seed, key_sizes)
        if self.symmetric_cryptography.verifier or self.symmetric_cryptography.decryptor:
            self.symmetric_cryptography.prev_verifier = self.symmetric_cryptography.verifier
            self.symmetric_cryptography.prev_decryptor = self.symmetric_cryptography.decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        # convert lifetime to seconds and add the 25% extra-margin (Part4/5.5.2)
        lifetime *= 1.25 * 0.001
        self.symmetric_cryptography.key_expiration = time.monotonic() + lifetime
        self.symmetric_cryptography.verifier = VerifierAesCbc(sigkey)
        self.symmetric_cryptography.decryptor = DecryptorAesCbc(key, init_vec)


class SecurityPolicyBasic256Sha256(SecurityPolicy):
    """
    Security Basic 256Sha256
    A suite of algorithms that uses Sha256 as Key-Wrap-algorithm
    and 256-Bit (32 bytes) for encryption algorithms.

    - SymmetricSignatureAlgorithm_HMAC-SHA2-256
      https://tools.ietf.org/html/rfc4634
    - SymmetricEncryptionAlgorithm_AES256-CBC
      http://www.w3.org/2001/04/xmlenc#aes256-cbc
    - AsymmetricSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - AsymmetricEncryptionAlgorithm_RSA-OAEP-SHA1
      http://www.w3.org/2001/04/xmlenc#rsa-oaep
    - KeyDerivationAlgorithm_P-SHA2-256
      http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha256
    - CertificateSignatureAlgorithm_RSA-PKCS15-SHA2-256
      http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    - Basic256Sha256_Limits
        -> DerivedSignatureKeyLength: 256 bits
        -> MinAsymmetricKeyLength: 2048 bits
        -> MaxAsymmetricKeyLength: 4096 bits
        -> SecureChannelNonceLength: 32 bytes
    """

    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    AsymmetricSignatureURI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    secure_channel_nonce_length = 32

    signature_key_size = 32
    symmetric_key_size = 32

    @staticmethod
    def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes) -> bytes:
        return uacrypto.encrypt_rsa_oaep(pubkey, data)

    @staticmethod
    def sign_asymmetric(privkey: RSAPrivateKey, data: bytes) -> bytes:
        return uacrypto.sign_sha256(privkey, data)

    @override
    def __init__(
        self,
        peer_cert: x509.Certificate | bytes,
        host_cert: x509.Certificate | None,
        host_privkey: RSAPrivateKey,
        mode: MessageSecurityMode,
        permission_ruleset: PermissionRuleset | None = None,
        host_cert_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        if isinstance(peer_cert, bytes):
            peer_cert = uacrypto.x509_from_der(peer_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography: Cryptography = Cryptography(MessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.signer = SignerSha256(host_privkey)
        self.asymmetric_cryptography.verifier = VerifierSha256(peer_cert)
        self.asymmetric_cryptography.encryptor = EncryptorRsa(peer_cert, uacrypto.encrypt_rsa_oaep, 42)
        self.asymmetric_cryptography.decryptor = DecryptorRsa(host_privkey, uacrypto.decrypt_rsa_oaep, 42)
        self.symmetric_cryptography: Cryptography = Cryptography(mode)
        self.Mode = mode
        self.peer_certificate = uacrypto.der_from_x509(peer_cert)
        self.host_certificate = uacrypto.der_from_x509(host_cert)
        host_cert_chain = host_cert_chain or []
        self.host_certificate_chain = [uacrypto.der_from_x509(cert) for cert in host_cert_chain]
        self.permissions = permission_ruleset

    @override
    def make_local_symmetric_key(self, secret: bytes, seed: bytes) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        self.symmetric_cryptography.signer = SignerHMac256(sigkey)
        self.symmetric_cryptography.encryptor = EncryptorAesCbc(key, init_vec)

    @override
    def make_remote_symmetric_key(self, secret: bytes, seed: bytes, lifetime: float) -> None:
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)

        (sigkey, key, init_vec) = uacrypto.p_sha256(secret, seed, key_sizes)
        if self.symmetric_cryptography.verifier or self.symmetric_cryptography.decryptor:
            self.symmetric_cryptography.prev_verifier = self.symmetric_cryptography.verifier
            self.symmetric_cryptography.prev_decryptor = self.symmetric_cryptography.decryptor
            self.symmetric_cryptography.prev_key_expiration = self.symmetric_cryptography.key_expiration

        # lifetime is in ms
        self.symmetric_cryptography.key_expiration = time.monotonic() + (lifetime * 0.001)
        self.symmetric_cryptography.verifier = VerifierHMac256(sigkey)
        self.symmetric_cryptography.decryptor = DecryptorAesCbc(key, init_vec)


def encrypt_asymmetric(pubkey: RSAPublicKey, data: bytes, policy_uri: str) -> tuple[bytes, str]:
    """
    Encrypt data with pubkey using an asymmetric algorithm.
    The algorithm is selected by policy_uri.
    Returns a tuple (encrypted_data, algorithm_uri)
    """
    for cls in (
        SecurityPolicyBasic256Sha256,
        SecurityPolicyBasic256,
        SecurityPolicyBasic128Rsa15,
        SecurityPolicyAes128Sha256RsaOaep,
        SecurityPolicyAes256Sha256RsaPss,
    ):
        if policy_uri == cls.URI:
            return (cls.encrypt_asymmetric(pubkey, data), cls.AsymmetricEncryptionURI)
    if not policy_uri or policy_uri == SecurityPolicyNone.URI:
        return data, ""
    raise UaError(f"Unsupported security policy `{policy_uri}`")


_T = TypeVar("_T", bound=SecurityPolicy)


class SecurityPolicyFactory(Generic[_T]):
    """
    Helper class for creating server-side SecurityPolicy.
    Server has one certificate and private key, but needs a separate
    SecurityPolicy for every client and client's certificate
    """

    def __init__(
        self,
        cls: type[_T],
        mode: MessageSecurityMode,
        certificate: x509.Certificate | None = None,
        private_key: RSAPrivateKey | None = None,
        permission_ruleset: PermissionRuleset | None = None,
        certificate_chain: Sequence[x509.Certificate] | None = None,
    ) -> None:
        self.cls = cls
        self.mode = mode
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
        self.permission_ruleset = permission_ruleset

    def matches(self, uri: str, mode: MessageSecurityMode | None = None) -> bool:
        return self.cls.URI == uri and (mode is None or self.mode == mode)

    def create(self, peer_certificate: x509.Certificate | None) -> _T:
        return self.cls(
            peer_certificate,
            self.certificate,
            self.private_key,
            self.mode,
            permission_ruleset=self.permission_ruleset,
            host_cert_chain=self.certificate_chain,
        )


def sign_asymmetric(privkey: RSAPrivateKey, data: bytes, policy_uri: str) -> tuple[bytes, str]:
    """
    Sign data with privkey using an asymmetric algorithm.
    The algorithm is selected by policy_uri.
    Returns a tuple (signature, algorithm_uri)
    """
    for cls in (
        SecurityPolicyBasic256Sha256,
        SecurityPolicyBasic256,
        SecurityPolicyBasic128Rsa15,
        SecurityPolicyAes128Sha256RsaOaep,
        SecurityPolicyAes256Sha256RsaPss,
    ):
        if policy_uri == cls.URI:
            return (cls.sign_asymmetric(privkey, data), cls.AsymmetricSignatureURI)
    if not policy_uri or policy_uri == SecurityPolicyNone.URI:
        return data, ""
    raise UaError(f"Unsupported security policy `{policy_uri}`")


# policy, mode, security_level
SECURITY_POLICY_TYPE_MAP = {
    SecurityPolicyType.NoSecurity: [SecurityPolicyNone, MessageSecurityMode.None_, 0],
    SecurityPolicyType.Basic128Rsa15_Sign: [SecurityPolicyBasic128Rsa15, MessageSecurityMode.Sign, 1],
    SecurityPolicyType.Basic128Rsa15_SignAndEncrypt: [
        SecurityPolicyBasic128Rsa15,
        MessageSecurityMode.SignAndEncrypt,
        2,
    ],
    SecurityPolicyType.Basic256_Sign: [SecurityPolicyBasic256, MessageSecurityMode.Sign, 11],
    SecurityPolicyType.Basic256_SignAndEncrypt: [SecurityPolicyBasic256, MessageSecurityMode.SignAndEncrypt, 21],
    SecurityPolicyType.Basic256Sha256_Sign: [SecurityPolicyBasic256Sha256, MessageSecurityMode.Sign, 50],
    SecurityPolicyType.Basic256Sha256_SignAndEncrypt: [
        SecurityPolicyBasic256Sha256,
        MessageSecurityMode.SignAndEncrypt,
        70,
    ],
    SecurityPolicyType.Aes128Sha256RsaOaep_Sign: [SecurityPolicyAes128Sha256RsaOaep, MessageSecurityMode.Sign, 55],
    SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt: [
        SecurityPolicyAes128Sha256RsaOaep,
        MessageSecurityMode.SignAndEncrypt,
        75,
    ],
    SecurityPolicyType.Aes256Sha256RsaPss_Sign: [SecurityPolicyAes256Sha256RsaPss, MessageSecurityMode.Sign, 60],
    SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt: [
        SecurityPolicyAes256Sha256RsaPss,
        MessageSecurityMode.SignAndEncrypt,
        80,
    ],
}
