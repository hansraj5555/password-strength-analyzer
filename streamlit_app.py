# streamlit_app.py
import re
import math
import hashlib
import requests
import streamlit as st

# --- PasswordAnalyzer (adapted from your code) ---
class PasswordAnalyzer:
    def __init__(self, common_passwords_file='common_passwords.txt'):
        self.common_passwords = self.load_common_passwords(common_passwords_file)
    
    def load_common_passwords(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            return {'password', '123456', 'password123', 'qwerty', 'abc123', 
                   'letmein', 'monkey', '1234567890', 'welcome', 'admin'}
    
    def calculate_entropy(self, password):
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        if charset_size == 0:
            return 0.0
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def estimate_crack_time(self, entropy):
        attempts_per_sec = 10_000_000_000
        total_combinations = 2 ** entropy
        seconds = total_combinations / (2 * attempts_per_sec)
        if seconds < 1:
            return 'Instant'
        elif seconds < 60:
            return f'{seconds:.1f} seconds'
        elif seconds < 3600:
            return f'{seconds/60:.1f} minutes'
        elif seconds < 86400:
            return f'{seconds/3600:.1f} hours'
        elif seconds < 31536000:
            return f'{seconds/86400:.1f} days'
        elif seconds < 31536000 * 100:
            return f'{seconds/31536000:.1f} years'
        else:
            return 'Millions of years'
    
    def check_breach(self, password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        try:
            url = f'https://api.pwnedpasswords.com/range/{prefix}'
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = response.text.splitlines()
                for h in hashes:
                    parts = h.split(':')
                    if parts and parts[0] == suffix:
                        count = int(parts[1]) if len(parts) > 1 else 1
                        return True, count
                return False, 0
            else:
                return None, 0
        except Exception:
            return None, 0
    
    def check_strength(self, password):
        if not password:
            return {'score': 0, 'strength': 'Empty', 'entropy': 0.0, 'issues': ['Password is empty'], 'suggestions': ['Enter a password'], 'time_to_crack': 'Instant'}
        score = 0
        issues = []
        suggestions = []
        length = len(password)
        if length < 8:
            issues.append(f'Too short ({length} characters)')
            suggestions.append('Use at least 8 characters (12+ recommended)')
        elif length < 12:
            score += 1
            suggestions.append('Consider using 12+ characters for better security')
        elif length < 16:
            score += 2
        else:
            score += 3
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        if not has_lower:
            issues.append('No lowercase letters'); suggestions.append('Add lowercase letters')
        if not has_upper:
            issues.append('No uppercase letters'); suggestions.append('Add uppercase letters')
        if not has_digit:
            issues.append('No numbers'); suggestions.append('Add numbers')
        if not has_special:
            issues.append('No special characters'); suggestions.append('Add special characters (!@#$%^&*)')
        score += char_types
        if password.lower() in self.common_passwords:
            issues.append('This is a commonly used password'); suggestions.append('Avoid common passwords'); score = max(0, score - 3)
        if re.search(r'(.)\1{2,}', password):
            issues.append('Contains repeated characters'); suggestions.append('Avoid repeated characters'); score = max(0, score - 1)
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            issues.append('Contains sequential characters'); suggestions.append('Avoid sequential patterns'); score = max(0, score - 1)
        if re.search(r'\d{4,}', password):
            issues.append('Contains long number sequences'); suggestions.append('Mix letters and numbers throughout')
        entropy = self.calculate_entropy(password)
        if score <= 2:
            strength = 'Weak'; color = 'red'
        elif score <= 4:
            strength = 'Fair'; color = 'orange'
        elif score <= 6:
            strength = 'Good'; color = 'yellow'
        else:
            strength = 'Strong'; color = 'green'
        time_to_crack = self.estimate_crack_time(entropy)
        return {'score': score, 'strength': strength, 'color': color, 'entropy': entropy, 'issues': issues or ['No major issues found'], 'suggestions': suggestions or ['Your password looks good!'], 'time_to_crack': time_to_crack}

# --- Streamlit UI ---
st.set_page_config(page_title="Password Strength Analyzer", layout="centered")
st.title("🔐 Password Strength Analyzer (Web)")

analyzer = PasswordAnalyzer()

password = st.text_input("Enter password", type="password", placeholder="Type a password to analyze")
show = st.checkbox("Show password", value=False)
if show:
    # show the value in plain text (but it's also visible in the browser)
    st.write("Password:", password)

if password:
    result = analyzer.check_strength(password)
    st.subheader(f"Strength: {result['strength']}")
    st.progress(min(max(result['score'] / 8, 0), 1))
    st.write(f"Entropy: **{result['entropy']:.1f} bits**")
    st.write(f"Estimated time to crack: **{result['time_to_crack']}**")
    st.markdown("**Issues:**")
    for issue in result['issues']:
        st.write(f"- {issue}")
    st.markdown("**Suggestions:**")
    for suggestion in result['suggestions']:
        st.write(f"- {suggestion}")
    st.markdown("---")
    if st.button("Check if password has been breached"):
        with st.spinner("Checking Have I Been Pwned..."):
            breached, count = analyzer.check_breach(password)
            if breached is None:
                st.error("Unable to check breach database (network/API issue).")
            elif breached:
                st.warning(f"This password was found in {count:,} breaches! DO NOT use it.")
            else:
                st.success("This password was NOT found in known breaches (k-anonymity check).")

else:
    st.info("Enter a password to analyze. No passwords are stored by this app (breach check uses k-anonymity).")
# --- End of streamlit_app.py ---