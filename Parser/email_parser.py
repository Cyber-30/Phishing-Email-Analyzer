from email import policy
from email.parser import BytesParser

def parse_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        body_part = msg.get_body(preferencelist=('plain', 'html'))
        body = body_part.get_content() if body_part else None

        raw_data = {
            "From": msg.get("From"),
            "To": msg.get("To"),
            "Subject": msg.get("Subject"),
            "Date": msg.get("Date"),
            "Body": body
        }

        return raw_data

    except FileNotFoundError:
        print("❌ File not found. Please check the path.")
    except Exception as e:
        print("❌ Error parsing email:", e)


# ---- Main Program ----
file_path = input("Enter the path for the email file (.eml): ")
email_data = parse_email(file_path)

if email_data:
    choice = input("Want to see the headers with the body part? (y/n): ").strip().lower()

    if choice == 'n':
        # Show only headers
        for key, value in email_data.items():
            if key != "Body":
                print(f"\n{key} = {value}")
    else:
        # Show headers + body
        for key, value in email_data.items():
            print(f"\n{key} = {value}")
