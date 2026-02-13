Password Strength Checker
A Python-based security tool that analyzes password strength using pattern detection, entropy calculation, and brute-force attack simulation.
Features

Multi-criteria validation: Length, character complexity, pattern detection
Real-time analysis: Instant feedback on password strength
Brute-force estimation: Calculates crack time based on modern GPU attack speeds
Common password detection: Validates against database of compromised credentials
Secure input handling: Hidden password entry using getpass module

Installation
bashgit clone https://github.com/NISTALTALSON/Password-Strength-Checker.git
cd Password-Strength-Checker
No external dependencies required - uses Python standard library only.
Usage
bashpython3 password_checker.py
Follow the interactive menu to:

Check password strength
View security tips
Understand password vulnerabilities

How It Works
The tool evaluates passwords using:

Regex pattern matching for character type detection (uppercase, lowercase, digits, special chars)
Combinatorial analysis to estimate brute-force crack time
Pattern detection for common vulnerabilities (repeated characters, sequences)
Scoring algorithm with weighted criteria (0-6 scale)

Requirements

Python 3.6+

Example Output
Password Analysis Results
=========================
Strength: STRONG
Score: 6/6
Estimated crack time: 2.3 million years

Detailed Feedback:
  ✓ Good length (12+ characters)
  ✓ Contains lowercase letters
  ✓ Contains uppercase letters
  ✓ Contains numbers
  ✓ Contains special characters
Security Note
This tool is for educational purposes and local analysis only. Passwords are not stored or transmitted.
