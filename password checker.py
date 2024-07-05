import re

def password_strength(password):
    # Criteria for password strength
    length_criteria = len(password) >= 8
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    number_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[\W_]', password) is not None

    # Checking how many criteria are met
    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria])
    
    # Feedback based on the number of criteria met
    if criteria_met == 5:
        feedback = "Very Strong"
    elif criteria_met == 4:
        feedback = "Strong"
    elif criteria_met == 3:
        feedback = "Moderate"
    elif criteria_met == 2:
        feedback = "Weak"
    else:
        feedback = "Very Weak"

    return feedback, length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria

def main():
    password = input("Enter a password to check its strength: ")
    feedback, length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria = password_strength(password)

    print(f"Password Strength: {feedback}")
    print("Criteria Met:")
    print(f" - Length (>= 8): {'Yes' if length_criteria else 'No'}")
    print(f" - Uppercase Letters: {'Yes' if uppercase_criteria else 'No'}")
    print(f" - Lowercase Letters: {'Yes' if lowercase_criteria else 'No'}")
    print(f" - Numbers: {'Yes' if number_criteria else 'No'}")
    print(f" - Special Characters: {'Yes' if special_char_criteria else 'No'}")

if __name__ == "__main__":
    main()
