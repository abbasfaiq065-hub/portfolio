import math
import string
import getpass

print("=" * 45)
print(" Password Strength Checker")
print("=" * 45)

password = getpass.getpass("Enter password: ")

length = len(password)

has_lower = any(c.islower() for c in password)
has_upper = any(c.isupper() for c in password)
has_digit = any(c.isdigit() for c in password)
has_special = any(c in string.punctuation for c in password)

charset = 0
if has_lower:
    charset += 26
if has_upper:
    charset += 26
if has_digit:
    charset += 10
if has_special:
    charset += len(string.punctuation)

entropy = 0
if charset > 0 and length > 0:
    entropy = length * math.log2(charset)

# Educational estimate only
guesses_per_second = 10_000_000_000 # 10 billion guesses/sec
combinations = charset ** length if charset else 1
seconds = combinations / guesses_per_second

def format_time(seconds):
    if seconds < 1:
        return "Instantly"
    units = [
        ("centuries", 60*60*24*365*100),
        ("years", 60*60*24*365),
        ("days", 60*60*24),
        ("hours", 60*60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    for name, value in units:
        if seconds >= value:
            amount = int(seconds // value)
            return f"{amount} {name}"
    return "Instantly"

score = 0

if length >= 12:
    score += 2
elif length >= 8:
    score += 1

score += has_lower
score += has_upper
score += has_digit
score += has_special

if score <= 2:
    strength = "Very Weak"
elif score == 3:
    strength = "Weak"
elif score == 4:
    strength = "Moderate"
elif score == 5:
    strength = "Strong"
else:
    strength = "Very Strong"

print("\n========== RESULTS ==========")
print(f"Length : {length}")
print(f"Lowercase : {'Yes' if has_lower else 'No'}")
print(f"Uppercase : {'Yes' if has_upper else 'No'}")
print(f"Numbers : {'Yes' if has_digit else 'No'}")
print(f"Special Characters : {'Yes' if has_special else 'No'}")
print(f"Entropy : {entropy:.1f} bits")
print(f"Strength : {strength}")
print(f"Est. Crack Time : {format_time(seconds)}")
print("(Estimate assumes a very fast offline attack.)")

print("\nSuggestions:")
if length < 12:
    print("- Use at least 12 characters.")
if not has_lower:
    print("- Add lowercase letters.")
if not has_upper:
    print("- Add uppercase letters.")
if not has_digit:
    print("- Add numbers.")
if not has_special:
    print("- Add special characters.")
if score == 6:
    print("- Excellent password!")

input("\nPress Enter to exit...")
