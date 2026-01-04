import re
import hashlib

def load_password_list(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip().lower() for line in f.readlines()]
    except FileNotFoundError:
        return []

common_passwords = load_password_list("../data/common_passwords.txt")
breached_passwords = load_password_list("../data/breached_passwords.txt")

def check_password_strength(password):
    score = 0
    feedback = []

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if len(password) >= 12:
        score += 3
    elif len(password) >= 8:
        score += 2
    else:
        score += 1
        feedback.append("Password should be at least 8 characters long.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 2
    else:
        feedback.append("Add at least one number.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2
    else:
        feedback.append("Add at least one special character.")

    if password.lower() in common_passwords:
        score -= 2
        feedback.append("Avoid commonly used passwords.")

    if password.lower() in breached_passwords:
        score -= 3
        feedback.append("This password has appeared in known data breaches.")

    score = max(score, 0)

    if score <= 3:
        level = "Weak"
    elif score <= 6:
        level = "Medium"
    elif score <= 8:
        level = "Strong"
    else:
        level = "Very Strong"

    return score, level, feedback
