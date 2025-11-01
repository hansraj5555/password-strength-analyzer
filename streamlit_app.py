import streamlit as st
import re
import math
import hashlib
import requests

st.set_page_config(page_title="🔐 Password Strength Analyzer", layout="centered")

# Add custom CSS
st.markdown("""
<style>
    .main {
        padding: 2rem;
    }
    .stTextInput > div > div > input {
        font-size: 1.2rem;
    }
</style>
""", unsafe_allow_html=True)

# Title
st.title("🔐 Password Strength Analyzer")
st.markdown("---")

# Password input
password = st.text_input("Enter Password:", type="password", key="password")
show_password = st.checkbox("Show password")

if show_password and password:
    st.text_input("Your password:", value=password, disabled=True)

if password:
    # Calculate entropy
    def calculate_entropy(pwd):
        charset_size = 0
        if re.search(r'[a-z]', pwd): charset_size += 26
        if re.search(r'[A-Z]', pwd): charset_size += 26
        if re.search(r'[0-9]', pwd): charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', pwd): charset_size += 32
        return len(pwd) * math.log2(charset_size) if charset_size > 0 else 0
    
    # Check strength
    score = 0
    issues = []
    suggestions = []
    
    # Length check
    if len(password) < 8:
        issues.append(f"Too short ({len(password)} characters)")
        suggestions.append("Use at least 12 characters")
    elif len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    else:
        score += 1
    
    # Character diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    score += sum([has_lower, has_upper, has_digit, has_special])
    
    if not has_lower: 
        issues.append("No lowercase letters")
        suggestions.append("Add lowercase letters")
    if not has_upper:
        issues.append("No uppercase letters")
        suggestions.append("Add uppercase letters")
    if not has_digit:
        issues.append("No numbers")
        suggestions.append("Add numbers")
    if not has_special:
        issues.append("No special characters")
        suggestions.append("Add special characters (!@#$%^&*)")
    
    # Determine strength
    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 4:
        strength = "Fair"
        color = "orange"
    elif score <= 6:
        strength = "Good"
        color = "yellow"
    else:
        strength = "Strong"
        color = "green"
    
    entropy = calculate_entropy(password)
    
    # Display results
    st.markdown(f"## Strength: <span style='color:{color}'>{strength}</span>", unsafe_allow_html=True)
    
    # Progress bar
    st.progress(score / 8)
    
    # Metrics
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Score", f"{score}/8")
    with col2:
        st.metric("Entropy", f"{entropy:.1f} bits")
    
    # Issues
    if issues:
        st.markdown("### ⚠️ Issues")
        for issue in issues:
            st.markdown(f"- {issue}")
    
    # Suggestions
    if suggestions:
        st.markdown("### 💡 Suggestions")
        for suggestion in suggestions:
            st.markdown(f"- {suggestion}")
    else:
        st.success("✅ Your password looks strong!")
    
    # Breach check
    st.markdown("---")
    if st.button("🔍 Check if Password Has Been Breached"):
        with st.spinner("Checking breach database..."):
            try:
                sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
                prefix = sha1_hash[:5]
                suffix = sha1_hash[5:]
                
                response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
                
                if response.status_code == 200:
                    breached = False
                    count = 0
                    for line in response.text.split('\r\n'):
                        if line.startswith(suffix):
                            breached = True
                            count = int(line.split(':')[1])
                            break
                    
                    if breached:
                        st.error(f"⚠️ WARNING: This password has been found in {count:,} data breaches! DO NOT use it.")
                    else:
                        st.success("✅ Good news! This password has not been found in known breaches.")
                else:
                    st.warning("Unable to check breach database. Please try again.")
            except Exception as e:
                st.error(f"Error checking breaches: {str(e)}")

st.markdown("---")
st.caption("Powered by Have I Been Pwned API | All checks are private and secure")