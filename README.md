# Automated-Differential-Fuzzing-for-Detecting-WAF-Backend-Parsing-Discrepancies

A grammar-driven HTTP fuzzing framework designed to uncover parsing discrepancies between Web Application Firewalls (WAFs) and backend web frameworks.
The fuzzer generates HTTP requests, applies one of five structured mutation categories, and compares how the WAF and backend interpret each request.
The goal: identify bypass opportunities, normalization weaknesses, and parser inconsistencies that lead to real-world evasions.

**Features**
- Grammar-based request generator
- Produces syntactically valid HTTP requests for deterministic fuzzing.
- Five mutation categories (explicitly tagged):
    * Mismatched Content-Type headers
    * Multipart boundary edits
    * Missing/altered headers
    * Header folding & obfuscation
    * JSON structure mutations
- Modular mutator with category tagging
- Dual-engine evaluation: Sends each mutated request to:
    * A WAF (e.g., ModSecurity CRS)
    * A backend (e.g., Flask/Express)
- Discrepancy detection engine: Automatically flags bypasses and interpretation differences.

**Installation Requirements**
- Python 3.x
- requests
- rich (optional, for colorful CLI output)

Install dependencies:
pip install -r requirements.txt



**Mutation Categories**
1. Mismatched Content-Type: Abuses header/body mismatch ambiguities
2. Multipart Boundary Edits: Alters MIME boundary behavior to confuse parsers
3. Missing/Altered Headers: Removes or rewrites critical HTTP headers
4. Header Folding/ObfuscationUses legacy formatting to bypass naive parsing
5. JSON Structure Mutations: Breaks or obfuscates JSON structure in subtle ways

Every generated mutation is tagged with one of these.

**Research Context**

This project accompanies a formal evaluation of how WAFs and backend parsers differ when handling malformed or intentionally ambiguous HTTP requests.
The fuzzer attempts to reproduce parsing edge cases similar to those explored in the “Waffled” parser discrepancy paper, including the use of a request normalizer.
The methodology includes:


**Academic Note**

This fuzzer was developed as part of a security-focused class project exploring:
- WAF evasion
- HTTP parser inconsistencies
- Grammar-driven fuzzing
- Security evaluation methodologies

It is intended for research, education, and defense testing only.

**Disclaimer!!**

This tool is intended for authorized research and testing only.
Do not use it on systems you do not own or have explicit permission to test.
The authors are not responsible for misuse.


