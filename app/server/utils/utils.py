import re

def identify_contact_info(string):
    # Regular expressions patterns for phone number and email address
    phone_number_pattern = r"^\d{10}$"
    # email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if re.match(phone_number_pattern, string):
        return "_id"
    else:
        return "email"