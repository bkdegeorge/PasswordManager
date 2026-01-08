"""
Password strength analysis module.
"""

import re
import math
from typing import Dict, Tuple


class PasswordStrengthAnalyzer:
    """Analyze password strength and provide feedback."""

    def __init__(self):
        self.common_passwords = {
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
            'master', 'sunshine', 'ashley', '123123', 'welcome', 'admin',
            'password1', '1234567890', 'password123', 'qwerty123'
        }

    def analyze(self, password: str) -> Dict:
        """
        Analyze password and return strength score and feedback.
        Returns: dict with score (0-100), strength_text, and feedback list
        """
        if not password:
            return {
                'score': 0,
                'strength': 'Very Weak',
                'feedback': ['Password cannot be empty']
            }

        score = 0
        feedback = []

        # Length scoring (max 30 points)
        length = len(password)
        if length < 8:
            feedback.append('Password should be at least 8 characters long')
            score += length * 2
        elif length < 12:
            feedback.append('Consider using 12 or more characters')
            score += 16 + (length - 8) * 2
        elif length < 16:
            score += 24 + (length - 12)
        else:
            score += 30

        # Character variety scoring (max 40 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password))

        char_types = sum([has_lower, has_upper, has_digit, has_symbol])

        if char_types == 1:
            feedback.append('Use a mix of uppercase, lowercase, numbers, and symbols')
            score += 5
        elif char_types == 2:
            feedback.append('Add numbers and symbols for better security')
            score += 15
        elif char_types == 3:
            feedback.append('Great! Consider adding more character variety')
            score += 30
        else:
            score += 40

        # Pattern detection (penalties)
        if self._has_sequential_chars(password):
            feedback.append('Avoid sequential characters (abc, 123)')
            score -= 10

        if self._has_repeated_chars(password):
            feedback.append('Avoid repeated characters (aaa, 111)')
            score -= 10

        # Common password check (severe penalty)
        if password.lower() in self.common_passwords:
            feedback.append('This is a commonly used password!')
            score = max(0, score - 50)

        # Dictionary word check (simple)
        if self._contains_common_words(password):
            feedback.append('Avoid using common dictionary words')
            score -= 15

        # Entropy bonus (max 30 points)
        entropy = self._calculate_entropy(password)
        entropy_score = min(30, int(entropy / 3))
        score += entropy_score

        # Normalize score to 0-100
        score = max(0, min(100, score))

        # Determine strength text
        if score < 25:
            strength = 'Very Weak'
        elif score < 50:
            strength = 'Weak'
        elif score < 70:
            strength = 'Fair'
        elif score < 85:
            strength = 'Strong'
        else:
            strength = 'Very Strong'

        if not feedback:
            feedback.append('Excellent password!')

        return {
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'length': length,
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_symbols': has_symbol,
            'entropy': round(entropy, 2)
        }

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters like abc, 123."""
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and
                ord(password[i+2]) == ord(password[i]) + 2):
                return True
        return False

    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated characters like aaa, 111."""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False

    def _contains_common_words(self, password: str) -> bool:
        """Check if password contains common dictionary words."""
        common_words = [
            'love', 'password', 'admin', 'user', 'test', 'hello',
            'welcome', 'login', 'pass', 'secret', 'master', 'admin'
        ]
        password_lower = password.lower()
        return any(word in password_lower for word in common_words)

    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0

        # Determine character pool size
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'\d', password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += 32  # approximate for special chars

        if pool_size == 0:
            return 0.0

        # Entropy = log2(pool_size ^ length)
        entropy = len(password) * math.log2(pool_size)
        return entropy

    def get_strength_color(self, score: int) -> str:
        """Get color code for strength visualization."""
        if score < 25:
            return '#d9534f'  # Red
        elif score < 50:
            return '#f0ad4e'  # Orange
        elif score < 70:
            return '#f7dc6f'  # Yellow
        elif score < 85:
            return '#5bc0de'  # Light Blue
        else:
            return '#5cb85c'  # Green

    def time_to_crack(self, password: str, guesses_per_second: int = 1e9) -> str:
        """
        Estimate time to crack password.
        Assumes 1 billion guesses per second by default (modern GPU).
        """
        analysis = self.analyze(password)
        entropy = analysis['entropy']

        # Total possible combinations
        combinations = 2 ** entropy

        # Time in seconds
        seconds = combinations / guesses_per_second

        # Convert to human readable
        if seconds < 1:
            return "Less than a second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 2592000:  # 30 days
            return f"{int(seconds/86400)} days"
        elif seconds < 31536000:  # 1 year
            return f"{int(seconds/2592000)} months"
        else:
            years = int(seconds/31536000)
            if years > 1e6:
                return f"{years:.2e} years (practically uncrackable)"
            return f"{years:,} years"
