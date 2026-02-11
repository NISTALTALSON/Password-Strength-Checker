"""
Password Strength Checker
A beginner friendly project for learning password security concepts

"""
import re
import getpass

def check_password_strength(password):
    """
    Analyzes password strength based on multiple criteria
    Returns: (score,strength_level,feedback)
    """
    score=0
    feedback= []

    #length check
    length =len(password)
    if length >=12 :
        score += 2
        feedback.append("Good length (12+ characters)")
    elif length >=8:
        score +=1
        feedback.append("Acceptable length (8=11 characters)")
    else :
        feedback.append("Too short (less than 8 characters)")

    #checking for lowercase

    if re.search(r'[a-z]', password):
        score +=1
        feedback.append("Contains Lowercase letters")
    else:
        feedback.append("Missing lowercase letters")

    #checking for uppercase letters
    if re.search(r'[A-Z]', password):
        score +=1
        feedback.append("Contains uppercase letters")
    else:
        feedback.append("Missing uppercase letters")

    #checking for digits

    if re.search(r'\d', password):
        score +=1
        feedback.append("Contains numbers")
    else:
        feedback.append("Missing numbers")

    #checking for special characters

    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
        score += 1
        feedback.append("Contains special characters")
    else:
        feedback.append("Missing special characters")

    #checking for common patterns

    common_patterns =[

        (r'(.)\1{2,}', "Contains repeated characters"),
        (r'(abc|123|qwerty|password)', "Contains common patterns"),
        (r'^\d+$', " Only contains numbers"),
        (r'^[a-zA-Z]+$', " Only contains letters")

    ]
    for pattern,message in common_patterns:
        if re.search(pattern, password.lower()):
            score -= 1
            feedback.append(message)

    #determine strength level
    if score>=6:
        strength = "STRONG"
        color ="\33[92m"
    elif score >=4:
        strength ="MODERATE"
        color ="\033[91m"
    else:
        strength = "WEAK"
        color = "\033[91m"
    return score,strength,feedback,color

def check_common_password(password):

    #most common passwords list taken from internet

    common_passwords = [
        '1234', '1234567', '1234567890',  
    'Aa123456', 'qwerty123',         
    'admin123', 'pass@123',            
    'abcd1234', 'password1',            
    '111111', '123123',                   
    'letmein1', 'welcome1',               
    'login123', 'user123',                
    'guest', 'test',                      
    'iloveyou1', 'dragon1234',            
    'football1', 'monkey123'
    'password', '123456', '123456789', '12345678', '12345',
        'qwerty', 'abc123', 'password1', '111111', '123123',
        'admin', 'letmein', 'welcome', 'monkey', 'dragon',
        'master', 'sunshine', 'princess', 'login', 'solo'
    ]

    #around 40 most used passwords are present

    return password.lower() in common_passwords

def estimate_crack_time(password):
    """
    Estimated timmes to crack password using brute force
    A simplied version for studying
    """
    charset_size=0
    if re.search(r'[a-z]',password):
        charset_size +=26
    if re.search(r'[A-Z]',password):
        charset_size += 26
    if re.search(r'\d',password):
        charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;~`]', password):
        charset_size += 32

    total_combinations = charset_size ** len(password)

    #lets just assume 1 billion attempts per second (modern GPU)
    attempts_per_second=1_000_000_000
    seconds_to_crack=total_combinations / (2*attempts_per_second)

    # converting to human readable time
    if seconds_to_crack < 1:
        return "Instantly"
    elif seconds_to_crack < 60:
        return f"{seconds_to_crack:.0f} seconds"
    elif seconds_to_crack < 3600:
        return f"{seconds_to_crack/60:.0f} minutes"
    elif seconds_to_crack < 86400:
        return f"{seconds_to_crack/3600:.1f} hours"
    elif seconds_to_crack < 31536000:
        return f"{seconds_to_crack/86400:.0f} days"
    elif seconds_to_crack < 31536000 * 100:
        return f"{seconds_to_crack/31536000:.0f} years"
    else:
        return "Millions of years"

def print_header():
    """Print program header"""
    print("\n" + "="*60)
    print("           PASSWORD STRENGTH CHECKER")
    print("      Learning Cybersecurity - Password Security")
    print("="*60 + "\n")


def print_tips():
    """Print password security tips"""
    print("\n" + "-"*60)
    print("PASSWORD SECURITY TIPS:")
    print("-"*60)
    tips = [
        "1. Use at least 12 characters (longer is better)",
        "2. Mix uppercase, lowercase, numbers, and symbols",
        "3. Avoid common words, patterns, and personal info",
        "4. Use unique passwords for different accounts",
        "5. Consider using a password manager",
        "6. Enable two-factor authentication (2FA) when possible"
    ]
    for tip in tips:
        print(f"  {tip}")
    print("-"*60 + "\n")


def main():
    """Main program loop"""
    print_header()
    
    while True:
        print("\nOptions:")
        print("1. Check a password")
        print("2. View security tips")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            # (hidden input)
            print("\nEnter a password to check (input will be hidden):")
            password = getpass.getpass("Password: ")
            
            if not password:
                print("\n⚠ No password entered!")
                continue
            
        
            score, strength, feedback, color = check_password_strength(password)
            is_common = check_common_password(password)
            crack_time = estimate_crack_time(password)
            
            # results
            print("\n" + "="*60)
            print(f"PASSWORD ANALYSIS RESULTS")
            print("="*60)
            
            print(f"\nStrength: {color}{strength}\033[0m")
            print(f"Score: {max(0, score)}/6")
            print(f"\nEstimated crack time: {crack_time}")
            
            if is_common:
                print("\n WARNING: This is a commonly used password!")
                print("   Never use this password for real accounts!")
            
            print(f"\nDetailed Feedback:")
            for item in feedback:
                print(f"  {item}")
            
            print("="*60)
            
        elif choice == '2':
            print_tips()
            
        elif choice == '3':
            print("\nThank you for learning about password security!")
            print("Stay safe online! \n")
            break
            
        else:
            print("\n Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted.\n")
    except Exception as e:
        print(f"\n An error occurred: {e}\n")









