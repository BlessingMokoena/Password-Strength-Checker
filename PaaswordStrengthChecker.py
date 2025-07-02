import re
import string
import math
import requests
import hashlib

class PasswordStrengthChecker:
    def __init__(self, password: str):
        self.password = password
        self.criteria = {
            "Minimum 8 characters": self._has_min_length,
            "At least one lowercase letter": self._has_lowercase,
            "At least one uppercase letter": self._has_uppercase,
            "At least one digit": self._has_digit,
            "At least one special character": self._has_special_char
        }

    def _has_min_length(self):
        return len(self.password) >= 8

    def _has_lowercase(self):
        return re.search(r"[a-z]", self.password) is not None

    def _has_uppercase(self):
        return re.search(r"[A-Z]", self.password) is not None

    def _has_digit(self):
        return re.search(r"\d", self.password) is not None

    def _has_special_char(self):
        return any(char in string.punctuation for char in self.password)

    def evaluate(self):
        results = {desc: check() for desc, check in self.criteria.items()}
        passed_checks = sum(results.values())
        strength_label = self._get_strength_label(passed_checks)
        entropy = self._calculate_entropy()
        pwned_count = self._check_pwned()
        return {
            "password": self.password,
            "passed": passed_checks,
            "total": len(self.criteria),
            "strength": strength_label,
            "details": results,
            "entropy": entropy,
            "pwned_count": pwned_count
        }

    def _get_strength_label(self, score):
        labels = {
            5: "Very Strong",
            4: "Strong",
            3: "Moderate",
            2: "Weak",
            1: "Very Weak",
            0: "Extremely Weak"
        }
        return labels.get(score, "Unknown")

    def _calculate_entropy(self):
        charset_size = 0
        if re.search(r"[a-z]", self.password):
            charset_size += 26
        if re.search(r"[A-Z]", self.password):
            charset_size += 26
        if re.search(r"\d", self.password):
            charset_size += 10
        if any(char in string.punctuation for char in self.password):
            charset_size += len(string.punctuation)
        if charset_size == 0:
            return 0.0
        entropy = len(self.password) * math.log2(charset_size)
        return round(entropy, 2)

    def _check_pwned(self):
        """
        Uses the Have I Been Pwned k-Anonymity API to check if the password
        has appeared in known breaches. Returns the number of times found.
        """
        sha1 = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
                return 0
            else:
                return -1  # API error
        except Exception:
            return -1  # Network/API error

def display_strength_meter(entropy):
    # 0-28: very weak, 28-36: weak, 36-60: moderate, 60-80: strong, 80+: very strong
    thresholds = [28, 36, 60, 80]
    bars = 20
    max_entropy = 100
    filled = int(entropy / max_entropy * bars)
    bar = "[" + "#" * filled + "-" * (bars - filled) + "]"
    if entropy < thresholds[0]:
        color = "\033[91m"  # Red
    elif entropy < thresholds[1]:
        color = "\033[93m"  # Yellow
    elif entropy < thresholds[2]:
        color = "\033[92m"  # Green
    elif entropy < thresholds[3]:
        color = "\033[96m"  # Cyan
    else:
        color = "\033[94m"  # Blue
    reset = "\033[0m"
    print(f"Entropy: {entropy:.2f} bits {color}{bar}{reset}")

def display_report(report):
    print(f"\nPassword Strength Report")
    print("-" * 30)
    print(f"Password: {'*' * len(report['password'])}")
    print(f"Strength: {report['strength']}")
    print(f"Passed {report['passed']} of {report['total']} checks\n")
    display_strength_meter(report["entropy"])
    print()
    for desc, passed in report["details"].items():
        status = "✓" if passed else "✗"
        print(f" [{status}] {desc}")

    if report["pwned_count"] == -1:
        print("\n  Could not check password breach status (network error).")
    elif report["pwned_count"] == 0:
        print("\n This password has not been found in known data breaches.")
    else:
        print(f"\n This password has appeared in data breaches {report['pwned_count']} times! Do NOT use it.")

    print()

if __name__ == "__main__":
    while True:
        user_input = input("Enter a password to evaluate: ")
        checker = PasswordStrengthChecker(user_input)
        result = checker.evaluate()
        display_report(result)

        if result["passed"] >= 4 and result["entropy"] >= 36 and (result["pwned_count"] == 0 or result["pwned_count"] == -1):
            print(" Password is strong enough.")
            break
        else:
            print(" Password is not strong enough. Please address the following:\n")
            for desc, passed in result["details"].items():
                if not passed:
                    print(f" - {desc}")
            if result["entropy"] < 36:
                print(" - Increase the password's length and variety to improve entropy.")
            if result["pwned_count"] > 0:
                print(" - Choose a password that is not found in data breaches.")
            print()
