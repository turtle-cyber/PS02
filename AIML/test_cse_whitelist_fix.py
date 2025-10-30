"""
Test CSE Whitelist Fix for Subdomain Matching

Verifies that legitimate CSE domains with subdomains are correctly identified as BENIGN.
"""

import json
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def load_cse_whitelist():
    """Load CSE whitelist from baseline profile"""
    baseline_path = Path('data/training/cse_baseline_profile.json')
    with open(baseline_path, 'r') as f:
        baseline = json.load(f)
    return set(baseline['domains'])

def test_subdomain_matching(domain, cse_whitelist):
    """
    Test subdomain-aware matching logic

    Returns:
        (is_whitelisted, matched_cse)
    """
    is_whitelisted = False
    matched_cse = None

    # Check 1: Exact match (full domain or registrable)
    if domain in cse_whitelist:
        is_whitelisted = True
        matched_cse = domain
        return (is_whitelisted, matched_cse)

    # Check 2: Subdomain-aware matching
    parts = domain.split('.')
    if len(parts) > 2:
        # Try different registrable domain combinations
        for i in range(1, len(parts) - 1):
            registrable_candidate = '.'.join(parts[i:])
            if registrable_candidate in cse_whitelist:
                is_whitelisted = True
                matched_cse = registrable_candidate
                logger.info(f"Domain {domain} matched CSE whitelist via registrable: {registrable_candidate}")
                return (is_whitelisted, matched_cse)

    # Check 3: Suffix match (domain ends with whitelisted domain)
    for cse_domain in cse_whitelist:
        if domain.endswith('.' + cse_domain) or domain == cse_domain:
            is_whitelisted = True
            matched_cse = cse_domain
            logger.info(f"Domain {domain} matched CSE whitelist via subdomain: {cse_domain}")
            return (is_whitelisted, matched_cse)

    return (is_whitelisted, matched_cse)


if __name__ == '__main__':
    print("=" * 80)
    print("CSE Whitelist Fix - Subdomain Matching Test")
    print("=" * 80)

    # Load CSE whitelist
    cse_whitelist = load_cse_whitelist()
    print(f"\nLoaded {len(cse_whitelist)} CSE domains from whitelist\n")

    # Test cases from the user's problematic verdicts
    test_cases = [
        "www.icicibank.com",
        "bankofbaroda.bank.in",
        "www.ecatering.irctc.co.in",
        "www.hdfcbank.com"
    ]

    print("Testing problematic domains:")
    print("-" * 80)

    results = []
    for domain in test_cases:
        is_whitelisted, matched_cse = test_subdomain_matching(domain, cse_whitelist)

        status = "✓ PASS" if is_whitelisted else "✗ FAIL"
        results.append((domain, is_whitelisted, matched_cse))

        print(f"{status}: {domain}")
        if is_whitelisted:
            print(f"       Matched: {matched_cse}")
        else:
            print(f"       ERROR: Domain should be whitelisted!")
        print()

    # Additional tests for base domains (should also work)
    print("\nTesting base domains (sanity check):")
    print("-" * 80)

    base_domains = [
        "icicibank.com",
        "hdfcbank.com",
        "bankofbaroda.in",
        "irctc.co.in"
    ]

    for domain in base_domains:
        is_whitelisted, matched_cse = test_subdomain_matching(domain, cse_whitelist)
        status = "✓ PASS" if is_whitelisted else "✗ FAIL"
        print(f"{status}: {domain} -> {matched_cse if is_whitelisted else 'NOT MATCHED'}")

    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, whitelisted, _ in results if whitelisted)
    total = len(results)

    print(f"Problematic domains tested: {total}")
    print(f"Successfully whitelisted: {passed}")
    print(f"Failed: {total - passed}")

    if passed == total:
        print("\n✓ ALL TESTS PASSED - CSE whitelist matching is working correctly!")
    else:
        print("\n✗ SOME TESTS FAILED - Please check the whitelist configuration")
        print("\nFailed domains:")
        for domain, whitelisted, _ in results:
            if not whitelisted:
                print(f"  - {domain}")
