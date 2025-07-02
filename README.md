# Password-Strength-Checker

A Python-based password strength checker that evaluates password complexity, calculates entropy, and checks for exposure in known data breaches using the Have I Been Pwned API.

**Features**

Strength Evaluation
Checks against 5 key security criteria:

Minimum 8 characters

At least one lowercase letter

At least one uppercase letter

At least one digit

At least one special character

Entropy Calculation
Measures password unpredictability using character set size and password length.

Data Breach Detection
Integrates with the Have I Been Pwned API to check if the password has been compromised in known breaches.

Strength Meter Visualization
Color-coded entropy bar to help visualize password strength.

Interactive CLI Report
Displays a detailed summary of passed criteria, entropy, and breach status.


**How It Works**

The user inputs a password.

The script checks the password against strength criteria.

Entropy is calculated based on character variety.

A SHA-1 hash of the password is sent (using k-anonymity) to the Pwned Passwords API.

A full strength report is displayed in the terminal.

If the password is weak, the user is prompted to improve it.



