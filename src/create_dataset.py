import csv
import random
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_PATH = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "cybersecurity_messages.csv"
)


random.seed(42)


BENIGN = [
    "The project meeting has been moved to tomorrow at {time}.",
    "Please review the project report before the meeting.",
    "The training session will begin at {time}.",
    "Your appointment has been confirmed for {day}.",
    "The software update was successfully installed.",
    "Please submit the assignment before the deadline.",
    "The quarterly report is available for review.",
    "The team discussion will take place tomorrow.",
    "Your application has been received successfully.",
    "The conference room has been reserved for the meeting.",
    "Please bring your identification card to the office.",
    "The scheduled maintenance will begin tonight.",
    "Your order has been processed successfully.",
    "The document has been uploaded to the company portal.",
    "The system backup completed successfully.",
    "Please review the attached document.",
    "The customer support meeting is scheduled for Monday.",
    "Your registration has been completed.",
    "The new software version is ready for installation.",
    "The department meeting starts at {time}.",
    "Your interview has been scheduled for {day}.",
    "Please confirm your attendance for the event.",
    "The report has been shared with the project team.",
    "The database maintenance was completed successfully.",
    "Your training certificate is now available.",
]


PHISHING = [
    "Your account has been suspended. Click here immediately to verify your identity.",
    "URGENT: Verify your bank account or access will be permanently blocked.",
    "Your password has expired. Login immediately to secure your account.",
    "Security alert: Confirm your credentials by clicking the link below.",
    "Your bank account requires immediate verification.",
    "Click here to verify your account and prevent it from being locked.",
    "Your payment account has been compromised. Login now.",
    "Confirm your username and password immediately to restore access.",
    "Your account will be closed unless you verify your information.",
    "Unusual activity was detected. Click the verification link immediately.",
    "Your banking session has expired. Login to reactivate your account.",
    "Verify your account information to prevent suspension.",
    "Your online banking access requires immediate confirmation.",
    "Security warning: verify your credentials using the link provided.",
    "Your account security requires urgent verification.",
    "Click the secure link to confirm your banking information.",
    "Your account has been flagged. Verify your identity immediately.",
    "Login now to prevent your account from being disabled.",
    "Your payment profile needs immediate verification.",
    "Confirm your account credentials to restore access.",
    "Your bank has detected suspicious activity. Verify your account now.",
    "Your account will be suspended unless you complete verification.",
    "Please login immediately to prevent unauthorized account closure.",
    "Click here to confirm your banking credentials.",
    "Your security verification is pending. Complete it immediately.",
]


SCAM = [
    "Congratulations! You have won a lottery prize of $50,000.",
    "You have been selected for a cash reward. Send your bank details.",
    "Claim your free prize before the offer expires.",
    "Invest today and earn guaranteed returns with no risk.",
    "You won a special reward. Pay a small fee to receive your prize.",
    "Send your payment details to receive your unexpected refund.",
    "Your investment has generated a guaranteed profit.",
    "Claim your exclusive lottery reward by paying the processing charge.",
    "You have won a brand-new smartphone. Pay the delivery fee.",
    "Receive a guaranteed investment return by transferring money today.",
    "Congratulations! You have been selected for a special cash bonus.",
    "Pay the processing fee to unlock your prize.",
    "You are eligible for a large financial reward.",
    "Claim your unexpected inheritance by paying the required fee.",
    "Earn thousands of dollars from a guaranteed investment opportunity.",
    "Your account has been selected for a special reward.",
    "You have won a vacation package. Pay the registration fee.",
    "Transfer a small amount to receive your much larger reward.",
    "Your exclusive cash reward is waiting for you.",
    "Pay a verification fee to receive your prize.",
    "Congratulations! Your number was selected for a cash promotion.",
    "You can double your money with this guaranteed investment.",
    "Claim your financial bonus before the offer expires.",
    "You have been chosen for a special money-making opportunity.",
]


SOCIAL_ENGINEERING = [
    "Your manager needs your password urgently. Send it immediately.",
    "This is an urgent request from the security team. Share your verification code.",
    "Please provide your OTP so we can complete account verification.",
    "Your colleague needs your login credentials to complete an important task.",
    "Send the verification code immediately or your access will be revoked.",
    "Please confirm your identity by providing your account information.",
    "Your administrator has requested your password for an urgent security check.",
    "Call the support team and provide the verification code.",
    "I need your OTP to complete the transaction for you.",
    "Please send your login credentials so I can fix the account.",
    "The security department requires your verification code immediately.",
    "Your supervisor asked me to collect your password.",
    "Please provide your authentication code to confirm your identity.",
    "Send your employee credentials so we can complete the request.",
    "The administrator needs your account details urgently.",
    "Please share the OTP you received on your phone.",
    "Your manager asked you to provide the login information.",
    "Give me the verification code so I can resolve the issue.",
    "The IT team needs your password for an urgent security check.",
    "Please provide your credentials to complete the verification.",
    "Send the authentication code immediately to avoid account problems.",
    "Your colleague requested your account password for an important task.",
    "Please share your security code so the transaction can continue.",
    "The support representative needs your OTP to verify your identity.",
    "Your administrator requires your credentials immediately.",
]


def generate_messages(templates, label, count):
    """Generate a balanced set of messages."""

    messages = []

    replacements = {
        "{time}": [
            "9 AM",
            "10 AM",
            "11 AM",
            "2 PM",
            "3 PM",
            "4 PM",
        ],
        "{day}": [
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
        ],
    }

    while len(messages) < count:
        template = random.choice(templates)

        message = template

        for placeholder, values in replacements.items():
            if placeholder in message:
                message = message.replace(
                    placeholder,
                    random.choice(values),
                )

        messages.append(
            {
                "text": message,
                "label": label,
            }
        )

    return messages


def main():
    dataset = []

    dataset.extend(
        generate_messages(
            BENIGN,
            "benign",
            100,
        )
    )

    dataset.extend(
        generate_messages(
            PHISHING,
            "phishing",
            100,
        )
    )

    dataset.extend(
        generate_messages(
            SCAM,
            "scam",
            100,
        )
    )

    dataset.extend(
        generate_messages(
            SOCIAL_ENGINEERING,
            "social_engineering",
            100,
        )
    )

    random.shuffle(dataset)

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_PATH,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=["text", "label"],
        )

        writer.writeheader()
        writer.writerows(dataset)

    print("=" * 70)
    print("CYBERMIND-NLP DATASET GENERATOR")
    print("=" * 70)

    print(f"\nDataset created:")
    print(OUTPUT_PATH)

    print(f"\nTotal messages: {len(dataset)}")

    print("\nClass distribution:")

    for label in [
        "benign",
        "phishing",
        "scam",
        "social_engineering",
    ]:
        count = sum(
            1
            for item in dataset
            if item["label"] == label
        )

        print(
            f"  {label}: {count}"
        )

    print("\nDataset generation completed.")


if __name__ == "__main__":
    main()