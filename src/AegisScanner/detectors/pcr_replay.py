"""
PCR Replay Engine - TPM Platform Configuration Register Replay

Implements TPM PCR extension replay to validate event log integrity.
Uses the formula: PCR[n] = Hash(PCR[n-1] || event_digest)

This is the CORE of Measured Boot attestation. Without PCR replay,
the scanner cannot detect event log tampering - the primary bootkit
evasion technique.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
from typing import Dict, List, Optional, Tuple
from enum import IntEnum


class HashAlgorithm(IntEnum):
    """TPM hash algorithm identifiers."""
    SHA1 = 0x0004
    SHA256 = 0x000B
    SHA384 = 0x000C
    SHA512 = 0x000D


class PCRReplayEngine:
    """
    TPM PCR replay engine for event log validation.
    
    Implements the TPM 2.0 PCR extension algorithm:
        PCR[n] = Hash(PCR[n-1] || event_digest)
    
    This allows validation of event log integrity by replaying
    all measurements and comparing against actual TPM state.
    """
    
    def __init__(self, hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        """
        Initialize PCR replay engine.
        
        Args:
            hash_algorithm: Hash algorithm to use (default: SHA256)
        """
        self.hash_algorithm = hash_algorithm
        self.hash_size = self._get_hash_size(hash_algorithm)
        
        # Initialize all PCR banks to zero
        self.pcr_banks = {i: b'\x00' * self.hash_size for i in range(24)}
        
        # Track extension history for debugging
        self.extension_history = []
    
    def _get_hash_size(self, algorithm: HashAlgorithm) -> int:
        """Get hash output size in bytes."""
        sizes = {
            HashAlgorithm.SHA1: 20,
            HashAlgorithm.SHA256: 32,
            HashAlgorithm.SHA384: 48,
            HashAlgorithm.SHA512: 64
        }
        return sizes.get(algorithm, 32)
    
    def _hash(self, data: bytes) -> bytes:
        """
        Hash data using configured algorithm.
        
        Args:
            data: Data to hash
            
        Returns:
            Hash digest
        """
        if self.hash_algorithm == HashAlgorithm.SHA1:
            return hashlib.sha1(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(data).digest()
        else:
            return hashlib.sha256(data).digest()
    
    def extend_pcr(self, pcr_index: int, digest: bytes) -> bytes:
        """
        Extend PCR with new measurement.
        
        Implements: PCR[n] = Hash(PCR[n-1] || digest)
        
        Args:
            pcr_index: PCR index (0-23)
            digest: Measurement digest to extend
            
        Returns:
            New PCR value after extension
            
        Raises:
            ValueError: If PCR index is invalid or digest size is wrong
        """
        if not 0 <= pcr_index < 24:
            raise ValueError(f"Invalid PCR index: {pcr_index}")
        
        if len(digest) != self.hash_size:
            raise ValueError(
                f"Invalid digest size: {len(digest)} (expected {self.hash_size})"
            )
        
        # Get current PCR value
        current_value = self.pcr_banks[pcr_index]
        
        # Calculate new value: Hash(current || digest)
        extended_value = self._hash(current_value + digest)
        
        # Update PCR bank
        self.pcr_banks[pcr_index] = extended_value
        
        # Record extension for debugging
        self.extension_history.append({
            'pcr_index': pcr_index,
            'previous': current_value.hex(),
            'digest': digest.hex(),
            'result': extended_value.hex()
        })
        
        return extended_value
    
    def replay_event_log(self, events: List[Dict]) -> Dict[int, bytes]:
        """
        Replay entire TCG event log.
        
        Processes all events in order, extending PCRs with each
        measurement. Returns final PCR values for comparison
        against actual TPM state.
        
        Args:
            events: List of TCG event log entries, each containing:
                - pcr_index: PCR to extend
                - digests: List of digest info dicts with:
                    - algorithm: Hash algorithm ID
                    - digest: Hex-encoded digest value
        
        Returns:
            Dictionary mapping PCR index to final value
        """
        for event in events:
            pcr_idx = event['pcr_index']
            
            # Process each digest in the event
            for digest_info in event.get('digests', []):
                # Only process digests matching our algorithm
                if digest_info['algorithm'] == self.hash_algorithm:
                    try:
                        digest = bytes.fromhex(digest_info['digest'])
                        self.extend_pcr(pcr_idx, digest)
                    except (ValueError, KeyError) as e:
                        print(f"[WARNING] Failed to process event: {e}")
                        continue
        
        return self.pcr_banks.copy()
    
    def validate_against_tpm(
        self,
        tpm_pcrs: Dict[int, bytes],
        pcr_range: Optional[Tuple[int, int]] = None
    ) -> List[Dict]:
        """
        Compare replayed PCRs against actual TPM state.
        
        Args:
            tpm_pcrs: Actual PCR values from TPM
            pcr_range: Optional (start, end) tuple to limit validation
        
        Returns:
            List of findings for mismatched PCRs
        """
        findings = []
        
        # Determine PCR range to validate
        if pcr_range:
            start, end = pcr_range
        else:
            start, end = 0, 8  # Default: validate PCRs 0-7 (firmware)
        
        for pcr_idx in range(start, end):
            calculated = self.pcr_banks.get(pcr_idx, b'\x00' * self.hash_size)
            actual = tpm_pcrs.get(pcr_idx, b'\x00' * self.hash_size)
            
            if calculated != actual:
                findings.append({
                    'detector': 'pcr_replay',
                    'severity': 'critical',
                    'title': f'PCR {pcr_idx} replay mismatch',
                    'description': (
                        f'PCR {pcr_idx} calculated value does not match actual TPM value. '
                        f'This indicates event log tampering or measurement bypass.'
                    ),
                    'details': {
                        'pcr_index': pcr_idx,
                        'calculated': calculated.hex(),
                        'actual': actual.hex(),
                        'algorithm': self.hash_algorithm.name
                    },
                    'recommendation': (
                        'Investigate event log integrity. Bootkit may have '
                        'modified measurements or bypassed TPM extensions.'
                    )
                })
        
        return findings
    
    def reset(self):
        """Reset all PCRs to initial state (all zeros)."""
        self.pcr_banks = {i: b'\x00' * self.hash_size for i in range(24)}
        self.extension_history.clear()
    
    def get_pcr_value(self, pcr_index: int) -> bytes:
        """
        Get current value of specific PCR.
        
        Args:
            pcr_index: PCR index (0-23)
            
        Returns:
            Current PCR value
        """
        if not 0 <= pcr_index < 24:
            raise ValueError(f"Invalid PCR index: {pcr_index}")
        
        return self.pcr_banks[pcr_index]
    
    def get_extension_count(self, pcr_index: int) -> int:
        """
        Get number of extensions performed on PCR.
        
        Args:
            pcr_index: PCR index (0-23)
            
        Returns:
            Number of extensions
        """
        return sum(1 for h in self.extension_history 
                   if h['pcr_index'] == pcr_index)
    
    def export_state(self) -> Dict:
        """
        Export current PCR state for debugging/logging.
        
        Returns:
            Dictionary with PCR values and extension history
        """
        return {
            'algorithm': self.hash_algorithm.name,
            'pcr_values': {
                idx: value.hex() 
                for idx, value in self.pcr_banks.items()
            },
            'extension_count': {
                idx: self.get_extension_count(idx)
                for idx in range(24)
            },
            'history': self.extension_history
        }


