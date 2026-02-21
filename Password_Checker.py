import re
import math
import hashlib
import requests
import string
import secrets
from dataclasses import dataclass


# ============================================================
# CONFIGURATION
# ============================================================

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty",
    "abc123", "password1", "admin", "letmein"
}


# ============================================================
# DATA STRUCTURE
# ============================================================

@dataclass
class PasswordReport:
    score: int
    strength: str
    entropy: float
    breached: bool
    breach_count: int
    feedback: list


# ============================================================
# PASSWORD ANALYZER
# ============================================================

class SecurePassAnalyzer:

    def analyze(self, password: str) -> PasswordReport:
        score = 0
        feedback = []

        # 1️⃣ Length Check
        if len(password) >= 12:
            score += 3
        elif len(password) >= 8:
            score += 2
        else:
            feedback.append("Password should be at least 8 characters.")

        # 2️⃣ Character Variety
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters.")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers.")

        if re.search(r"[!@#$%^&*()_+=\-{};:,.<>?]", password):
            score += 2
        else:
            feedback.append("Add special characters.")

        # 3️⃣ Common Password Check
        if password.lower() in COMMON_PASSWORDS:
            feedback.append("This is a commonly used password.")
            score = 0

        # 4️⃣ Pattern Detection
        if re.search(r"(.)\1{2,}", password):
            feedback.append("Avoid repeated characters (e.g., aaa).")
            score -= 1

        # 5️⃣ Entropy Calculation
        entropy = self.calculate_entropy(password)

        # 6️⃣ Breach Check
        breached, breach_count = self.check_breach(password)

        # 7️⃣ Strength Rating
        strength = self.get_strength_label(score)

        return PasswordReport(
            score=max(score, 0),
            strength=strength,
            entropy=entropy,
            breached=breached,
            breach_count=breach_count,
            feedback=feedback
        )

    # --------------------------------------------------------

    def calculate_entropy(self, password: str) -> float:
        charset = 0

        if re.search(r"[a-z]", password):
            charset += 26
        if re.search(r"[A-Z]", password):
            charset += 26
        if re.search(r"\d", password):
            charset += 10
        if re.search(r"[!@#$%^&*()_+=\-{};:,.<>?]", password):
            charset += 32

        if charset == 0:
            return 0

        entropy = len(password) * math.log2(charset)
        return round(entropy, 2)

    # --------------------------------------------------------

    def get_strength_label(self, score: int) -> str:
        if score <= 2:
            return "VERY WEAK"
        elif score <= 4:
            return "WEAK"
        elif score <= 6:
            return "MODERATE"
        elif score <= 8:
            return "STRONG"
        else:
            return "VERY STRONG"

    # --------------------------------------------------------

    def check_breach(self, password: str):
        """
        Uses Have I Been Pwned k-Anonymity model
        """
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)

            if response.status_code != 200:
                return False, 0

            hashes = (line.split(":") for line in response.text.splitlines())

            for h_suffix, count in hashes:
                if h_suffix == suffix:
                    return True, int(count)

            return False, 0

        except requests.RequestException:
            return False, 0


# ============================================================
# PASSWORD GENERATOR
# ============================================================

def generate_secure_password(length=16):
    characters = (
        string.ascii_lowercase +
        string.ascii_uppercase +
        string.digits +
        "!@#$%^&*()_+-="
    )

    return ''.join(secrets.choice(characters) for _ in range(length))


# ============================================================
# CLI INTERFACE
# ============================================================

def main():
    analyzer = SecurePassAnalyzer()

    print("\n🔐 SecurePass Pro - Advanced Password Analyzer\n")

    while True:
        print("\n1. Analyze Password")
        print("2. Generate Secure Password")
        print("3. Exit")

        choice = input("Select option: ")

        if choice == "1":
            password = input("Enter password: ")

            report = analyzer.analyze(password)

            print("\n===== SECURITY REPORT =====")
            print("Strength:", report.strength)
            print("Score:", report.score)
            print("Entropy:", report.entropy, "bits")

            if report.breached:
                print(f"⚠ Breached {report.breach_count:,} times!")
            else:
                print("✓ Not found in known breaches.")

            if report.feedback:
                print("\nRecommendations:")
                for f in report.feedback:
                    print("-", f)

        elif choice == "2":
            pwd = generate_secure_password()
            print("\nGenerated Password:", pwd)

        elif choice == "3":
            print("Exiting. Stay secure.")
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()