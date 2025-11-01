import re
import math
import hashlib
import requests
import tkinter as tk
from tkinter import ttk, messagebox
import threading


class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
    
    def load_common_passwords(self):
        """Load common passwords from file or return default set"""
        try:
            with open('common_passwords.txt', 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return {'password', '123456', 'password123', 'qwerty', 'abc123', 
                   'letmein', 'monkey', '1234567890', 'welcome', 'admin'}
    
    def calculate_entropy(self, password):
        """Calculate password entropy"""
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
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def check_strength(self, password):
        """Analyze password strength and return detailed results"""
        if not password:
            return {
                'score': 0,
                'strength': 'Empty',
                'entropy': 0,
                'issues': ['Password is empty'],
                'suggestions': ['Enter a password'],
                'time_to_crack': 'Instant'
            }
        
        score = 0
        issues = []
        suggestions = []
        
        # Length check
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
        
        # Character diversity
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        
        if not has_lower:
            issues.append('No lowercase letters')
            suggestions.append('Add lowercase letters')
        if not has_upper:
            issues.append('No uppercase letters')
            suggestions.append('Add uppercase letters')
        if not has_digit:
            issues.append('No numbers')
            suggestions.append('Add numbers')
        if not has_special:
            issues.append('No special characters')
            suggestions.append('Add special characters (!@#$%^&*)')
        
        score += char_types
        
        # Common password check
        if password.lower() in self.common_passwords:
            issues.append('This is a commonly used password')
            suggestions.append('Avoid common passwords')
            score = max(0, score - 3)
        
        # Pattern detection
        if re.search(r'(.)\1{2,}', password):
            issues.append('Contains repeated characters')
            suggestions.append('Avoid repeated characters')
            score = max(0, score - 1)
        
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
            issues.append('Contains sequential characters')
            suggestions.append('Avoid sequential patterns')
            score = max(0, score - 1)
        
        if re.search(r'\d{4,}', password):
            issues.append('Contains long number sequences')
            suggestions.append('Mix letters and numbers throughout')
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        
        # Determine strength
        if score <= 2:
            strength = 'Weak'
            color = 'red'
        elif score <= 4:
            strength = 'Fair'
            color = 'orange'
        elif score <= 6:
            strength = 'Good'
            color = 'yellow'
        else:
            strength = 'Strong'
            color = 'green'
        
        # Calculate time to crack (simplified estimation)
        time_to_crack = self.estimate_crack_time(entropy)
        
        return {
            'score': score,
            'strength': strength,
            'color': color,
            'entropy': entropy,
            'issues': issues if issues else ['No major issues found'],
            'suggestions': suggestions if suggestions else ['Your password looks good!'],
            'time_to_crack': time_to_crack
        }
    
    def estimate_crack_time(self, entropy):
        """Estimate time to crack based on entropy"""
        # Assume 10 billion attempts per second (modern GPU)
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
        """Check if password has been in a breach using HIBP API"""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            url = f'https://api.pwnedpasswords.com/range/{prefix}'
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                hashes = response.text.split('\r\n')
                for h in hashes:
                    if h.startswith(suffix):
                        count = h.split(':')[1]
                        return True, int(count)
                return False, 0
            else:
                return None, 0
        except Exception as e:
            return None, 0


class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Strength Analyzer")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        
        self.analyzer = PasswordAnalyzer()
        self.show_password = False
        
        self.setup_ui()
    
    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title = tk.Label(header_frame, text="🔐 Password Strength Analyzer", 
                        font=('Arial', 20, 'bold'), bg='#2c3e50', fg='white')
        title.pack(pady=20)
        
        # Main content
        content_frame = tk.Frame(self.root, bg='white', padx=30, pady=20)
        content_frame.pack(fill='both', expand=True)
        
        # Password input
        input_label = tk.Label(content_frame, text="Enter Password:", 
                              font=('Arial', 12), bg='white')
        input_label.pack(anchor='w', pady=(0, 5))
        
        password_frame = tk.Frame(content_frame, bg='white')
        password_frame.pack(fill='x', pady=(0, 10))
        
        self.password_entry = tk.Entry(password_frame, font=('Arial', 12), 
                                      show='●', width=40)
        self.password_entry.pack(side='left', fill='x', expand=True)
        self.password_entry.bind('<KeyRelease>', self.on_password_change)
        
        self.show_btn = tk.Button(password_frame, text="👁", font=('Arial', 10),
                                 command=self.toggle_password, width=3)
        self.show_btn.pack(side='left', padx=(5, 0))
        
        # Strength bar
        self.strength_label = tk.Label(content_frame, text="Strength: Empty", 
                                      font=('Arial', 12, 'bold'), bg='white')
        self.strength_label.pack(anchor='w', pady=(10, 5))
        
        self.strength_bar = ttk.Progressbar(content_frame, length=540, 
                                           mode='determinate')
        self.strength_bar.pack(fill='x', pady=(0, 10))
        
        # Entropy display
        self.entropy_label = tk.Label(content_frame, text="Entropy: 0 bits", 
                                     font=('Arial', 10), bg='white', fg='gray')
        self.entropy_label.pack(anchor='w')
        
        self.crack_time_label = tk.Label(content_frame, text="Time to crack: N/A", 
                                        font=('Arial', 10), bg='white', fg='gray')
        self.crack_time_label.pack(anchor='w', pady=(0, 15))
        
        # Issues section
        issues_label = tk.Label(content_frame, text="Issues:", 
                               font=('Arial', 11, 'bold'), bg='white')
        issues_label.pack(anchor='w', pady=(10, 5))
        
        self.issues_text = tk.Text(content_frame, height=4, width=65, 
                                  font=('Arial', 9), bg='#fff5f5', 
                                  relief='flat', wrap='word')
        self.issues_text.pack(fill='x')
        self.issues_text.config(state='disabled')
        
        # Suggestions section
        suggestions_label = tk.Label(content_frame, text="Suggestions:", 
                                    font=('Arial', 11, 'bold'), bg='white')
        suggestions_label.pack(anchor='w', pady=(15, 5))
        
        self.suggestions_text = tk.Text(content_frame, height=4, width=65, 
                                       font=('Arial', 9), bg='#f0f8ff', 
                                       relief='flat', wrap='word')
        self.suggestions_text.pack(fill='x')
        self.suggestions_text.config(state='disabled')
        
        # Breach check button
        self.breach_btn = tk.Button(content_frame, text="Check if Password Has Been Breached", 
                                   font=('Arial', 11, 'bold'), bg='#e74c3c', 
                                   fg='white', command=self.check_breach, 
                                   cursor='hand2', relief='flat', padx=10, pady=8)
        self.breach_btn.pack(pady=(20, 10))
        
        self.breach_result = tk.Label(content_frame, text="", 
                                     font=('Arial', 10), bg='white', wraplength=500)
        self.breach_result.pack()
        
        # Footer
        footer = tk.Label(content_frame, 
                         text="Powered by Have I Been Pwned API", 
                         font=('Arial', 8), bg='white', fg='gray')
        footer.pack(side='bottom', pady=(20, 0))
    
    def toggle_password(self):
        self.show_password = not self.show_password
        self.password_entry.config(show='' if self.show_password else '●')
        self.show_btn.config(text='👁' if not self.show_password else '🙈')
    
    def on_password_change(self, event=None):
        password = self.password_entry.get()
        result = self.analyzer.check_strength(password)
        
        # Update strength bar
        self.strength_bar['value'] = (result['score'] / 8) * 100
        
        # Update strength label with color
        self.strength_label.config(text=f"Strength: {result['strength']}", 
                                  fg=result.get('color', 'black'))
        
        # Update entropy and crack time
        self.entropy_label.config(text=f"Entropy: {result['entropy']:.1f} bits")
        self.crack_time_label.config(text=f"Time to crack: {result['time_to_crack']}")
        
        # Update issues
        self.issues_text.config(state='normal')
        self.issues_text.delete(1.0, 'end')
        for i, issue in enumerate(result['issues'], 1):
            self.issues_text.insert('end', f"• {issue}\n")
        self.issues_text.config(state='disabled')
        
        # Update suggestions
        self.suggestions_text.config(state='normal')
        self.suggestions_text.delete(1.0, 'end')
        for i, suggestion in enumerate(result['suggestions'], 1):
            self.suggestions_text.insert('end', f"• {suggestion}\n")
        self.suggestions_text.config(state='disabled')
        
        # Clear breach result when password changes
        self.breach_result.config(text='')
    
    def check_breach(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password first!")
            return
        
        self.breach_btn.config(state='disabled', text='Checking...')
        self.breach_result.config(text='Checking breach database...', fg='orange')
        
        def check():
            breached, count = self.analyzer.check_breach(password)
            
            def update_ui():
                self.breach_btn.config(state='normal', 
                                      text='Check if Password Has Been Breached')
                
                if breached is None:
                    self.breach_result.config(
                        text='❌ Unable to check breach database. Please try again.',
                        fg='gray'
                    )
                elif breached:
                    self.breach_result.config(
                        text=f'⚠️ WARNING: This password has been found in {count:,} data breaches!\n'
                             f'DO NOT use this password. It is compromised.',
                        fg='red'
                    )
                else:
                    self.breach_result.config(
                        text='✅ Good news! This password has not been found in known breaches.\n'
                             'However, still ensure it meets strength requirements.',
                        fg='green'
                    )
            
            self.root.after(0, update_ui)
        
        thread = threading.Thread(target=check, daemon=True)
        thread.start()


def main():
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()