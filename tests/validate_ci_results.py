#!/usr/bin/env python3
"""
Ground Truth Validation System for Aegis-Boot CI/CD
Validates scanner results against known bootkit modifications
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class ValidationStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"

@dataclass
class GroundTruth:
    """Ground truth data for validation"""
    expected_hooks: List[str]
    expected_pcr_changes: Dict[int, str]
    expected_memory_regions: List[Tuple[int, int]]
    expected_entropy_anomalies: int
    expected_fv_modifications: int

@dataclass
class ValidationResult:
    """Result of a validation check"""
    check_name: str
    status: ValidationStatus
    expected: Any
    actual: Any
    message: str

class GroundTruthValidator:
    """Validates scanner results against ground truth"""
    
    def __init__(self, results_file: Path):
        self.results_file = results_file
        self.results = self._load_results()
        self.ground_truth = self._load_ground_truth()
        self.validation_results: List[ValidationResult] = []
    
    def _load_results(self) -> Dict:
        """Load scanner results from JSON"""
        try:
            with open(self.results_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load results: {e}")
            sys.exit(1)
    
    def _load_ground_truth(self) -> GroundTruth:
        """Load ground truth from side channel (UEFI variable)"""
        # In real implementation, this would read from a UEFI variable
        # that the bootkit writes to document its modifications
        
        # For CI, we use expected values based on bootkit implementation
        return GroundTruth(
            expected_hooks=[
                "ExitBootServices",
                "LoadImage",
                "StartImage",
                "SetVariable"
            ],
            expected_pcr_changes={
                0: "modified",  # BIOS/UEFI code
                7: "modified"   # Secure Boot policy
            },
            expected_memory_regions=[
                (0x100000, 0x200000),  # Low memory hook region
            ],
            expected_entropy_anomalies=2,  # Packed/encrypted sections
            expected_fv_modifications=1    # Modified DXE driver
        )
    
    def validate_hooks(self) -> ValidationResult:
        """Validate detected hooks against ground truth"""
        detected_hooks = []
        
        if 'hook_analysis' in self.results:
            for hook in self.results['hook_analysis'].get('detected_hooks', []):
                detected_hooks.append(hook.get('function', ''))
        
        expected_set = set(self.ground_truth.expected_hooks)
        detected_set = set(detected_hooks)
        
        missing = expected_set - detected_set
        extra = detected_set - expected_set
        
        if not missing and not extra:
            status = ValidationStatus.PASS
            message = "All expected hooks detected"
        elif missing:
            status = ValidationStatus.FAIL
            message = f"Missing hooks: {missing}"
        else:
            status = ValidationStatus.WARNING
            message = f"Extra hooks detected: {extra}"
        
        return ValidationResult(
            check_name="Hook Detection",
            status=status,
            expected=list(expected_set),
            actual=list(detected_set),
            message=message
        )
    
    def validate_pcr_changes(self) -> ValidationResult:
        """Validate PCR modifications"""
        pcr_issues = []
        
        if 'pcr_analysis' in self.results:
            for issue in self.results['pcr_analysis'].get('issues', []):
                if 'pcr' in issue:
                    pcr_num = issue['pcr']
                    pcr_issues.append(pcr_num)
        
        expected_pcrs = set(self.ground_truth.expected_pcr_changes.keys())
        detected_pcrs = set(pcr_issues)
        
        missing = expected_pcrs - detected_pcrs
        
        if not missing:
            status = ValidationStatus.PASS
            message = "All PCR modifications detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Missing PCR detections: {missing}"
        
        return ValidationResult(
            check_name="PCR Validation",
            status=status,
            expected=list(expected_pcrs),
            actual=list(detected_pcrs),
            message=message
        )
    
    def validate_memory_regions(self) -> ValidationResult:
        """Validate suspicious memory regions"""
        detected_regions = []
        
        if 'memory_analysis' in self.results:
            for region in self.results['memory_analysis'].get('suspicious_regions', []):
                start = region.get('start', 0)
                end = region.get('end', 0)
                detected_regions.append((start, end))
        
        # Check if expected regions overlap with detected
        found_count = 0
        for exp_start, exp_end in self.ground_truth.expected_memory_regions:
            for det_start, det_end in detected_regions:
                # Check for overlap
                if not (det_end < exp_start or det_start > exp_end):
                    found_count += 1
                    break
        
        expected_count = len(self.ground_truth.expected_memory_regions)
        
        if found_count == expected_count:
            status = ValidationStatus.PASS
            message = "All suspicious memory regions detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Found {found_count}/{expected_count} expected regions"
        
        return ValidationResult(
            check_name="Memory Region Detection",
            status=status,
            expected=expected_count,
            actual=found_count,
            message=message
        )
    
    def validate_entropy_anomalies(self) -> ValidationResult:
        """Validate entropy anomaly detection"""
        detected_anomalies = 0
        
        if 'entropy_analysis' in self.results:
            detected_anomalies = len(
                self.results['entropy_analysis'].get('high_entropy_regions', [])
            )
        
        expected = self.ground_truth.expected_entropy_anomalies
        
        # Allow some tolerance
        if abs(detected_anomalies - expected) <= 1:
            status = ValidationStatus.PASS
            message = "Entropy anomalies within expected range"
        else:
            status = ValidationStatus.WARNING
            message = f"Entropy anomalies: expected ~{expected}, got {detected_anomalies}"
        
        return ValidationResult(
            check_name="Entropy Analysis",
            status=status,
            expected=expected,
            actual=detected_anomalies,
            message=message
        )
    
    def validate_fv_modifications(self) -> ValidationResult:
        """Validate firmware volume modification detection"""
        detected_mods = 0
        
        if 'fv_analysis' in self.results:
            detected_mods = len(
                self.results['fv_analysis'].get('modified_drivers', [])
            )
        
        expected = self.ground_truth.expected_fv_modifications
        
        if detected_mods >= expected:
            status = ValidationStatus.PASS
            message = "FV modifications detected"
        else:
            status = ValidationStatus.FAIL
            message = f"Expected {expected} FV mods, found {detected_mods}"
        
        return ValidationResult(
            check_name="FV Modification Detection",
            status=status,
            expected=expected,
            actual=detected_mods,
            message=message
        )
    
    def calculate_metrics(self) -> Dict[str, float]:
        """Calculate TPR, FPR, and accuracy"""
        total_checks = len(self.validation_results)
        passed = sum(1 for r in self.validation_results if r.status == ValidationStatus.PASS)
        failed = sum(1 for r in self.validation_results if r.status == ValidationStatus.FAIL)
        warnings = sum(1 for r in self.validation_results if r.status == ValidationStatus.WARNING)
        
        # True Positive Rate (sensitivity)
        tpr = passed / total_checks if total_checks > 0 else 0.0
        
        # False Positive Rate (1 - specificity)
        # Warnings are considered potential false positives
        fpr = warnings / total_checks if total_checks > 0 else 0.0
        
        # Accuracy
        accuracy = (passed + warnings * 0.5) / total_checks if total_checks > 0 else 0.0
        
        return {
            'tpr': tpr,
            'fpr': fpr,
            'accuracy': accuracy,
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'total': total_checks
        }
    
    def run_validation(self) -> bool:
        """Run all validation checks"""
        print("\n" + "="*60)
        print("Ground Truth Validation")
        print("="*60 + "\n")
        
        # Run all validation checks
        self.validation_results = [
            self.validate_hooks(),
            self.validate_pcr_changes(),
            self.validate_memory_regions(),
            self.validate_entropy_anomalies(),
            self.validate_fv_modifications()
        ]
        
        # Print results
        for result in self.validation_results:
            status_symbol = {
                ValidationStatus.PASS: "✓",
                ValidationStatus.FAIL: "✗",
                ValidationStatus.WARNING: "⚠"
            }[result.status]
            
            status_color = {
                ValidationStatus.PASS: "\033[92m",  # Green
                ValidationStatus.FAIL: "\033[91m",  # Red
                ValidationStatus.WARNING: "\033[93m"  # Yellow
            }[result.status]
            
            print(f"{status_color}{status_symbol}\033[0m {result.check_name}")
            print(f"  Expected: {result.expected}")
            print(f"  Actual:   {result.actual}")
            print(f"  Message:  {result.message}\n")
        
        # Calculate and print metrics
        metrics = self.calculate_metrics()
        
        print("="*60)
        print("Validation Metrics")
        print("="*60)
        print(f"True Positive Rate (TPR):  {metrics['tpr']:.2%}")
        print(f"False Positive Rate (FPR): {metrics['fpr']:.2%}")
        print(f"Accuracy:                  {metrics['accuracy']:.2%}")
        print(f"\nResults: {metrics['passed']} passed, {metrics['failed']} failed, "
              f"{metrics['warnings']} warnings")
        print("="*60 + "\n")
        
        # Determine overall pass/fail
        # Pass if TPR >= 85% and no critical failures
        passed = metrics['tpr'] >= 0.85 and metrics['failed'] == 0
        
        if passed:
            print("\033[92m✓ VALIDATION PASSED\033[0m")
            return True
        else:
            print("\033[91m✗ VALIDATION FAILED\033[0m")
            return False

def main():
    if len(sys.argv) != 2:
        print("Usage: validate_ci_results.py <results.json>")
        sys.exit(1)
    
    results_file = Path(sys.argv[1])
    
    if not results_file.exists():
        print(f"[ERROR] Results file not found: {results_file}")
        sys.exit(1)
    
    validator = GroundTruthValidator(results_file)
    passed = validator.run_validation()
    
    sys.exit(0 if passed else 1)

if __name__ == "__main__":
    main()


