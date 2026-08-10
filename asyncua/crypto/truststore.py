"""
Functionality for checking a certificate based on:
- trusted (ca) certificates
- crl

"""

import logging
import re
from pathlib import Path

import anyio
from cryptography import x509

from asyncua.crypto.uacrypto import get_content, load_certificate

_logger = logging.getLogger("asyncuagds.validate")


def basic_ca_validator(_policy: x509.verification.Policy, _cert: x509.Certificate, ext: x509.BasicConstraints) -> None:
    if not ext.ca:
        raise ValueError("CA certificate must contain a basicConstraints extension with ca=true")


class TrustStore:
    """
    TrustStore is used to validate certificates in two ways:
    - Based on being absent in provided certificate revocation lists
    - The certificate or its issuer being present in a list of trusted certificates

    It doesn't check other content of extensions of the certificate.
    """

    def __init__(self, trust_locations: list[Path], crl_locations: list[Path]) -> None:
        """Constructor of the TrustStore.

        Args:
            trust_locations (list[Path]): one or multiple locations that contain trusted (ca) certificates.
                Type should be PEM or DER.
            crl_locations (list[Path]): one or multiple locations that contain CRL. Type should be PEM or DER.
        """

        self._trust_locations: list[Path] = trust_locations
        self._crl_locations: list[Path] = crl_locations

        self._trust_store: x509.verification.Store | None = None
        self._revoked_list: list[x509.RevokedCertificate] = []

        self.policy_builder = x509.verification.PolicyBuilder().extension_policies(
            ca_policy=x509.verification.ExtensionPolicy.permit_all().require_present(
                x509.BasicConstraints,
                x509.verification.Criticality.AGNOSTIC,
                basic_ca_validator,
            ),
            ee_policy=x509.verification.ExtensionPolicy.permit_all(),
        )

    @property
    def trust_locations(self) -> list[Path]:
        return self._trust_locations

    @property
    def crl_locations(self) -> list[Path]:
        return self._crl_locations

    async def load(self) -> None:
        """(Re)load both the trusted certificates and revocation lists."""
        await self.load_trust()
        await self.load_crl()

    async def load_trust(self) -> None:
        """(Re)load the trusted certificates."""
        certs: list[x509.Certificate] = []
        for location in self._trust_locations:
            certs.extend(await self._load_trust_location(location))
        self._trust_store = x509.verification.Store(certs)

    async def load_crl(self) -> None:
        """(Re)load the certificate revocation lists."""
        revoked: list[x509.RevokedCertificate] = []
        for location in self._crl_locations:
            revoked.extend(await self._load_crl_location(location))
        self._revoked_list = revoked

    def validate(self, certificate: x509.Certificate) -> bool:
        """Validates if a certificate is trusted, not revoked and lays in valid date range.

        Args:
            certificate (x509.Certificate): Certificate to check.
        """

        return self.is_trusted(certificate) and not self.is_revoked(certificate)

    def is_revoked(self, certificate: x509.Certificate) -> bool:
        """Check if the certificate is in the revocation lists.

        If no CRL is present, the certificate is not considered revoked.

        Args:
            certificate (x509.Certificate): Certificate to check.
        """
        is_revoked = False
        for revoked in self._revoked_list:
            if revoked.serial_number == certificate.serial_number:
                subject_cn = (
                    cn[0].value
                    if (cn := certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
                    else None
                )
                _logger.warning('Found revoked serial "%s" [CN=%s]', hex(certificate.serial_number), subject_cn)
                is_revoked = True
                break
        return is_revoked

    def is_trusted(self, certificate: x509.Certificate) -> bool:
        """Check if the provided certificate is considered trusted.

        For a self-signed to be trusted is must be placed in the trusted location

        Args:
            certificate (x509.Certificate): Certificate to check
        """
        if not self._trust_store:
            return False

        verifier = self.policy_builder.store(self._trust_store).build_client_verifier()
        try:
            verifier.verify(certificate, [])
            _logger.debug(
                "Use trusted certificate: [CN=%s]",
                cn[0].value if (cn := certificate.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)) else None,
            )
            return True
        except x509.verification.VerificationError:
            _logger.exception(
                "Not trusted certificate used: [CN=%s]",
                cn[0].value if (cn := certificate.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)) else None,
            )
        return False

    async def _load_trust_location(self, location: Path) -> list[x509.Certificate]:
        """Load from a single directory location the certificates and return them.

        Args:
            location (Path): location to scan for certificates.
        """
        certs: list[x509.Certificate] = []
        files = anyio.Path(location).glob("*.*")
        async for file_name in files:
            if re.match(".*(der|pem)", file_name.name.lower()):
                _logger.debug("Add certificate to TrustStore : '%s'", file_name)
                certs.append(await load_certificate(Path(file_name)))
        return certs

    async def _load_crl_location(self, location: Path) -> list[x509.RevokedCertificate]:
        """Load from a single directory location the CRLs and return certificates revoked by them.

        Args:
            location (Path): location to scan for crls.
        """
        revoked: list[x509.RevokedCertificate] = []
        files = anyio.Path(location).glob("*.*")
        async for file_name in files:
            if re.match(".*(der|pem)", file_name.name.lower()):
                _logger.debug("Add CRL to list : '%s'", file_name)
                crl = await self._load_crl(Path(file_name))
                revoked.extend(crl)
        return revoked

    @staticmethod
    async def _load_crl(crl_file_name: Path) -> x509.CertificateRevocationList:
        """Load a single CRL from file.

        Args:
            crl_file_name (Path): file to load

        Returns:
            x509.CertificateRevocationList: Loaded CRL
        """
        content = await get_content(crl_file_name)
        if crl_file_name.suffix.lower() == ".der":
            return x509.load_der_x509_crl(content)
        return x509.load_pem_x509_crl(content)
