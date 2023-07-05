import os
import requests
from pyotp import TOTP
import smtplib
from random import randint
from email.mime.text import MIMEText
from datetime import datetime
from server.utils.exceptions import (
    NotFoundException,
    UnauthorizedException,
    InternalServerErrorException
)
from server.database import delete_user, update_user


otp_key = os.environ.get('OTP_KEY')
email_address = os.environ.get('EMAIL_ADDRESS')
email_password = os.environ.get('EMAIL_PASSWORD')
sms_api_key = os.environ.get('SMS_API_KEY')

# Generate OTP
def generate_otp():
    return str(randint(100000, 999999))

# Send OTP via Phonenumber
def send_otp_sms(phone_number, otp):
    url = "https://www.fast2sms.com/dev/bulkV2"
    otp = int(otp)
    payload = f"variables_values={otp}&route=otp&numbers={phone_number}"
    headers = {
        'authorization': sms_api_key,
        'Content-Type': "application/x-www-form-urlencoded",
        'Cache-Control': "no-cache",
    }
    response = requests.request("POST", url, data=payload, headers=headers)
    print(response.content)
    if response and response.status_code == 200:
        return True
    else:
        return False

# Send OTP via Email
def send_otp_email(user_email, otp):
    # SMTP configuration
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    # Configure the email details
    sender_email = email_address
    sender_password = email_password

    subject = 'Login OTP Verification'
    body = f'Your OTP is: {otp}'

    message = MIMEText(body)
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = user_email

    # Connect to the SMTP server and send the email
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, [user_email], message.as_string())
    except Exception as e:
        print("Error Occured: {0}".format(e))
        raise InternalServerErrorException("Something went wrong while sending otp to the email.")

    
async def verify_otp(stored_user, otp, verification_attempts):

    if not stored_user:
        raise NotFoundException("User not found")

    # Get the stored OTP and its expiration time from the user document
    stored_otp = stored_user.get("otp")
    expiration_time = stored_user.get("otp_expiry")

    if not stored_otp or not expiration_time:
        raise NotFoundException("OTP not found")

    # Check if OTP has expired
    if datetime.now() > expiration_time:
        raise UnauthorizedException("OTP has expired")

    # Validate the OTP
    if stored_otp==otp:
        await update_user(stored_user["_id"],{
            "otp": "", 
            # "otp_expiry": ""
            })
        return True
    else:
        verification_attempts+=1
        if verification_attempts >= 3:
            await update_user(stored_user["_id"],{
                "otp": "",
                # "otp_expiry": ""
                })
            raise UnauthorizedException("Verification failed. Maximum attempts reached.")
        else:
            await update_user(stored_user["_id"],{"verification_attempts": verification_attempts})
            raise UnauthorizedException("Invalid OTP. Attempts remaining: {}/3".format(3 - verification_attempts))

async def verify_signup_otp(stored_user, otp, verification_attempts):
    
    if not stored_user:
        raise NotFoundException("User not found")

    # Get the stored OTP and its expiration time from the user document
    stored_otp = stored_user.get("otp")
    expiration_time = stored_user.get("otp_expiry")

    if not stored_otp or not expiration_time:
        await delete_user(stored_user["_id"])
        raise NotFoundException("OTP not found")

    # Check if OTP has expired
    if datetime.now() > expiration_time:
        await delete_user(stored_user["_id"])
        raise UnauthorizedException("OTP has expired")

    # Validate the OTP
    if stored_otp==otp:
        await update_user(stored_user["_id"],{"otp": "", "otp_expiry": ""})
        return True
    else:
        verification_attempts+=1
        if verification_attempts >= 3:
            await delete_user(stored_user["_id"])
            raise UnauthorizedException("Verification failed. Maximum attempts reached.")
        else:
            await update_user(stored_user["_id"],{"verification_attempts": verification_attempts})
            raise UnauthorizedException("Invalid OTP. Attempts remaining: {}/3".format(3 - verification_attempts))
