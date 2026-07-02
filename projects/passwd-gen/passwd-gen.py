import secrets
import string

generated = set()
SPECIAL = "!@#$%^&*()-_=+[]{};:,.<>?"

def generate_password(length):
    alphabet = string.ascii_letters + string.digits + SPECIAL

    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))

        if (
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in SPECIAL for c in password)
        ):
            if password not in generated:
                generated.add(password)
                return password

print("=" * 45)
print("       Strong Password Generator")
print("=" * 45)

while True:
    try:
        length = int(input("\nPassword length: "))

        if length < 4:
            print("Length must be at least 4.")
            continue

        password = generate_password(length)
        print(f"\nPassword: {password}")

    except ValueError:
        print("Please enter a valid number.")
        continue

    choice = input("\nGenerate another? (Y/N): ").strip().lower()
    if choice != "y":
        break

input("\nPress Enter to continue...")