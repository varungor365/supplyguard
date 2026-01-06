#!/usr/bin/env python3
"""
SupplyGuard - Supply Chain Security & Dependency Attack Detector
Detects malicious packages, typosquatting, and supply chain attacks

Author: Varun Goradhiya
GitHub: https://github.com/varungor365/supplyguard
"""

import argparse
import sys
import os
import json
import re
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
import tempfile

try:
    import requests
    from packaging import version
    import yaml
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[!] Run: pip install -r requirements.txt")
    sys.exit(1)

# Configuration
PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class PackageAnalyzer:
    """Analyze packages for malicious code and vulnerabilities"""
    
    def __init__(self, package_name: str, registry: str = 'pypi'):
        self.package_name = package_name
        self.registry = registry
        self.vulnerabilities = []
        self.malicious_indicators = []
        
    def analyze(self, sandbox: bool = False) -> Dict:
        """Comprehensive package analysis"""
        print(f"\n[+] Analyzing Package: {self.package_name}")
        print(f"    Registry: {self.registry}")
        print("=" * 60)
        
        # Fetch package metadata
        metadata = self.fetch_metadata()
        
        if not metadata:
            print("[!] Failed to fetch package metadata")
            return {}
            
        # Static analysis
        self.static_analysis(metadata)
        
        # Reputation check
        self.reputation_check(metadata)
        
        # Sandbox execution
        if sandbox:
            self.sandbox_execution()
            
        risk_score = self.calculate_risk_score()
        
        return {
            'package': self.package_name,
            'registry': self.registry,
            'vulnerabilities': self.vulnerabilities,
            'malicious_indicators': self.malicious_indicators,
            'risk_score': risk_score,
            'verdict': 'MALICIOUS' if risk_score > 75 else 'SUSPICIOUS' if risk_score > 40 else 'CLEAN'
        }
        
    def fetch_metadata(self) -> Dict:
        """Fetch package metadata from registry"""
        try:
            if self.registry == 'pypi':
                url = f"{PYPI_API}/{self.package_name}/json"
            elif self.registry == 'npm':
                url = f"{NPM_API}/{self.package_name}"
            else:
                return {}
                
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[!] Package not found: HTTP {response.status_code}")
                return {}
                
        except requests.exceptions.RequestException as e:
            print(f"[!] Network error: {e}")
            return {}
            
    def static_analysis(self, metadata: Dict):
        """Static code analysis for malicious patterns"""
        print("\n[+] Static Analysis")
        
        # Check for suspicious patterns in package name
        if self.check_typosquatting():
            self.malicious_indicators.append({
                'type': 'typosquatting',
                'severity': 'HIGH',
                'description': 'Package name similar to popular package'
            })
            print("    [!] Potential typosquatting detected")
            
        # Check maintainer info
        if self.registry == 'pypi' and 'info' in metadata:
            author_email = metadata['info'].get('author_email', '')
            
            # Suspicious email domains
            suspicious_domains = ['temp-mail.com', 'guerrillamail.com', 'mailinator.com']
            
            if any(domain in author_email for domain in suspicious_domains):
                self.malicious_indicators.append({
                    'type': 'suspicious_email',
                    'severity': 'MEDIUM',
                    'description': f'Temporary email domain: {author_email}'
                })
                print(f"    [!] Suspicious email: {author_email}")
                
        # Check for obfuscated code (would need to download package)
        print("    [+] Code obfuscation check: Requires download")
        
    def check_typosquatting(self) -> bool:
        """Check if package name is typosquatting popular packages"""
        popular_packages = {
            'pypi': ['tensorflow', 'numpy', 'pandas', 'requests', 'django', 'flask', 'pytorch'],
            'npm': ['react', 'vue', 'express', 'lodash', 'axios', 'webpack', 'typescript']
        }
        
        popular = popular_packages.get(self.registry, [])
        
        for pop_pkg in popular:
            # Simple Levenshtein distance (simplified)
            if self.similar_strings(self.package_name, pop_pkg):
                return True
                
        return False
        
    def similar_strings(self, s1: str, s2: str) -> bool:
        """Simple string similarity check"""
        if s1 == s2:
            return False
            
        # Check single character differences
        if len(s1) == len(s2):
            diff_count = sum(c1 != c2 for c1, c2 in zip(s1, s2))
            if diff_count == 1:
                return True
                
        # Check common typos
        typo_patterns = [
            (s2, s2 + 's'),  # plural
            (s2, s2 + '2'),  # version suffix
            (s2, s2.replace('o', '0')),  # o->0
            (s2, s2.replace('l', '1')),  # l->1
        ]
        
        for original, typo in typo_patterns:
            if s1 == typo:
                return True
                
        return False
        
    def reputation_check(self, metadata: Dict):
        """Check maintainer reputation"""
        print("\n[+] Reputation Analysis")
        
        if self.registry == 'pypi' and 'info' in metadata:
            # Check package age
            upload_time = metadata.get('urls', [{}])[0].get('upload_time', '')
            print(f"    Upload time: {upload_time}")
            
            # Check number of releases
            releases = metadata.get('releases', {})
            print(f"    Number of versions: {len(releases)}")
            
            if len(releases) < 3:
                self.malicious_indicators.append({
                    'type': 'new_package',
                    'severity': 'LOW',
                    'description': 'Package has very few releases'
                })
                print("    [!] Few releases (potentially new/untrusted)")
                
    def sandbox_execution(self):
        """Execute package in sandbox environment"""
        print("\n[+] Sandbox Execution")
        print("    [!] Requires Docker for safe execution")
        print("    [!] Skipping sandbox (not implemented in demo)")
        
        # Would execute package in Docker container
        # Monitor: network, filesystem, process activity
        
    def calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        severity_weights = {
            'CRITICAL': 40,
            'HIGH': 25,
            'MEDIUM': 10,
            'LOW': 5
        }
        
        for indicator in self.malicious_indicators:
            score += severity_weights.get(indicator['severity'], 0)
            
        return min(score, 100)


class DependencyScanner:
    """Scan project dependencies for vulnerabilities"""
    
    def __init__(self, project_path: str, project_type: str = 'python'):
        self.project_path = Path(project_path)
        self.project_type = project_type
        self.dependencies = []
        self.vulnerabilities = []
        
    def scan(self) -> Dict:
        """Scan project dependencies"""
        print(f"\n[+] Dependency Scan")
        print(f"    Project: {self.project_path}")
        print(f"    Type: {self.project_type}")
        print("=" * 60)
        
        # Parse dependency file
        self.parse_dependencies()
        
        # Check each dependency
        self.check_vulnerabilities()
        
        # Check for dependency confusion
        self.check_dependency_confusion()
        
        return {
            'project': str(self.project_path),
            'total_dependencies': len(self.dependencies),
            'vulnerabilities': self.vulnerabilities,
            'risk_level': self.calculate_risk_level()
        }
        
    def parse_dependencies(self):
        """Parse dependency file"""
        print("\n[+] Parsing Dependencies")
        
        if self.project_type == 'python':
            req_file = self.project_path / 'requirements.txt'
            
            if req_file.exists():
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        
                        if line and not line.startswith('#'):
                            # Parse package==version
                            if '==' in line:
                                pkg, ver = line.split('==')
                                self.dependencies.append({'name': pkg, 'version': ver})
                            else:
                                self.dependencies.append({'name': line, 'version': None})
                                
                print(f"    ✓ Found {len(self.dependencies)} dependencies")
            else:
                print("    [!] No requirements.txt found")
                
        elif self.project_type == 'npm':
            pkg_file = self.project_path / 'package.json'
            
            if pkg_file.exists():
                with open(pkg_file, 'r') as f:
                    data = json.load(f)
                    
                deps = data.get('dependencies', {})
                
                for name, ver in deps.items():
                    self.dependencies.append({'name': name, 'version': ver})
                    
                print(f"    ✓ Found {len(self.dependencies)} dependencies")
            else:
                print("    [!] No package.json found")
                
    def check_vulnerabilities(self):
        """Check dependencies against vulnerability databases"""
        print("\n[+] Vulnerability Check")
        
        # Known vulnerable packages (demo data)
        known_vulns = {
            'requests': {
                '2.25.0': ['CVE-2023-32681'],
                '2.26.0': ['CVE-2023-32681']
            },
            'django': {
                '3.0.0': ['CVE-2021-35042'],
                '3.1.0': ['CVE-2021-35042']
            }
        }
        
        for dep in self.dependencies:
            pkg_name = dep['name']
            pkg_ver = dep['version']
            
            if pkg_name in known_vulns and pkg_ver in known_vulns[pkg_name]:
                cves = known_vulns[pkg_name][pkg_ver]
                
                self.vulnerabilities.append({
                    'package': pkg_name,
                    'version': pkg_ver,
                    'cves': cves,
                    'severity': 'CRITICAL'
                })
                
                print(f"    [!] VULNERABLE: {pkg_name}=={pkg_ver}")
                print(f"        CVEs: {', '.join(cves)}")
                
        if not self.vulnerabilities:
            print("    ✓ No known vulnerabilities found")
        else:
            print(f"    [!] Found {len(self.vulnerabilities)} vulnerable packages")
            
    def check_dependency_confusion(self):
        """Check for dependency confusion attacks"""
        print("\n[+] Dependency Confusion Check")
        
        # Look for internal/private package names
        internal_patterns = ['company-', 'internal-', 'private-']
        
        for dep in self.dependencies:
            pkg_name = dep['name']
            
            if any(pattern in pkg_name for pattern in internal_patterns):
                print(f"    [!] WARNING: Potential internal package: {pkg_name}")
                print("        Ensure using private registry with --index-url")
                
    def calculate_risk_level(self) -> str:
        """Calculate overall risk level"""
        crit_count = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
        
        if crit_count > 0:
            return 'CRITICAL'
        elif len(self.vulnerabilities) > 5:
            return 'HIGH'
        elif len(self.vulnerabilities) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'


class SBOMGenerator:
    """Generate Software Bill of Materials"""
    
    def __init__(self, dependencies: List[Dict]):
        self.dependencies = dependencies
        
    def generate_cyclonedx(self, output_file: str):
        """Generate CycloneDX SBOM"""
        print(f"\n[+] Generating SBOM (CycloneDX)")
        
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'version': 1,
            'components': []
        }
        
        for dep in self.dependencies:
            component = {
                'type': 'library',
                'name': dep['name'],
                'version': dep.get('version', 'unknown')
            }
            sbom['components'].append(component)
            
        with open(output_file, 'w') as f:
            json.dump(sbom, f, indent=2)
            
        print(f"    ✓ SBOM saved to: {output_file}")
        print(f"    ✓ Components: {len(sbom['components'])}")


def main():
    parser = argparse.ArgumentParser(
        description='SupplyGuard - Supply Chain Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan project dependencies
  python supplyguard.py --scan-project . --type python
  
  # Analyze suspicious package
  python supplyguard.py --analyze-package malicious-pkg --registry pypi --sandbox
  
  # Generate SBOM
  python supplyguard.py --scan-project . --sbom cyclonedx
        '''
    )
    
    parser.add_argument('--scan-project', metavar='PATH', help='Scan project dependencies')
    parser.add_argument('--analyze-package', metavar='PACKAGE', help='Analyze specific package')
    parser.add_argument('--type', choices=['python', 'npm', 'maven'], default='python',
                       help='Project type')
    parser.add_argument('--registry', choices=['pypi', 'npm'], default='pypi',
                       help='Package registry')
    parser.add_argument('--sandbox', action='store_true', help='Execute in sandbox')
    parser.add_argument('--sbom', choices=['cyclonedx', 'spdx'], help='Generate SBOM')
    parser.add_argument('--output', default='sbom.json', help='SBOM output file')
    
    args = parser.parse_args()
    
    # Print banner
    print("""
╔═══════════════════════════════════════════════════════════╗
║  SupplyGuard v2.0 - Supply Chain Security Scanner        ║
║  Author: Varun Goradhiya                                  ║
║  GitHub: github.com/varungor365/supplyguard               ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Scan project mode
    if args.scan_project:
        if not os.path.exists(args.scan_project):
            print(f"[!] Error: Project path '{args.scan_project}' not found")
            sys.exit(1)
            
        scanner = DependencyScanner(args.scan_project, args.type)
        results = scanner.scan()
        
        # Generate SBOM if requested
        if args.sbom and scanner.dependencies:
            generator = SBOMGenerator(scanner.dependencies)
            
            if args.sbom == 'cyclonedx':
                generator.generate_cyclonedx(args.output)
                
        # Print summary
        print(f"\n[+] Scan Summary")
        print(f"    Total dependencies: {results['total_dependencies']}")
        print(f"    Vulnerabilities: {len(results['vulnerabilities'])}")
        print(f"    Risk level: {results['risk_level']}")
        
    # Analyze package mode
    elif args.analyze_package:
        analyzer = PackageAnalyzer(args.analyze_package, args.registry)
        results = analyzer.analyze(sandbox=args.sandbox)
        
        # Print results
        print(f"\n[+] Analysis Results")
        print(f"    Package: {results['package']}")
        print(f"    Risk score: {results['risk_score']}/100")
        print(f"    Verdict: {results['verdict']}")
        print(f"    Malicious indicators: {len(results['malicious_indicators'])}")
        
        for indicator in results['malicious_indicators']:
            print(f"      - {indicator['type']}: {indicator['description']}")
            
    else:
        parser.print_help()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
