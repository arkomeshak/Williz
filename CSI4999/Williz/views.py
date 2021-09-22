import hashlib
import random

from django.http import request, response, HttpResponse, HttpResponseRedirect
from django.db import transaction, IntegrityError
from django.contrib import messages
from django.shortcuts import render
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
# Model Imports
from .models import *
# Other imports
from random import choices, seed
import datetime
from time import time

"""
============================================= Constants & Globals ======================================================
"""
URL_SAFE_CHARS = "0123456789abcdefghIjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ–_"
BASE_URL = settings.BASE_URL # Get the base URL from settings.py for use in email links
# If we needed to add a new user, and give it a code in the DB, we simply need to add to the below constant list
USER_TYPES = ("admin", "realtor", "appraiser", "lender")
CODE_TO_USER_TYPE = {user_code: user_type for user_code, user_type in enumerate(USER_TYPES)}
USER_TYPE_TO_CODE = {USER_TYPES[i]: i for i in range(len(USER_TYPES))}
STATES = () # TODO: make a const list of 2-letter state codes



ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Create your views here.

def index(request):
    return HttpResponse("<h1>Hello Williz!</h1>")

def login(request):
    context = {}
    return render(request, "Williz/login.html", context)

def register(request):
    context = {}
    return render(request, "Williz/register.html", context)

def profile(request):
    context = {}
    return render(request, "Williz/profile.html", context)

def resetPassword(request):
    context = {}
    return render(request, "Williz/resetPassword.html", context)

def resetPassword_Handler(request):
    context = {}

    email = request.POST["email"]
    user = User.objects.get(email=email)
    chars = []
    for i in range(10):
        chars.append(random.choice(ALPHABET))
    verificationKey = "".join(chars)
    request.session["resetID"] = verificationKey
    with transaction.atomic():
        ForgotPassword = RequestReset(verification_str = verificationKey,
                                      user = user)
        ForgotPassword.save()
    RequestReset.objects.get(verification_str = verificationKey).verification_str
    
    request.session["email"] = User.objects.get(email = email).email
    try:
        message = f"Greetings,\n\n" + \
                    f"The following code is to verify your email for a password reset valid for 10 minutes:\n\n" + \
                    f"{verificationKey}\n" +\
                    f"\nIf you find this link has expired please submit another verification request from the login page."\
                    + f"\n\nRegards,\nThe Williz team"
        send_mail(
            "Williz Email Verification",
            message,
            "williznotifmail@gmail.com",
            [email],
            fail_silently=False
        )
    except Exception as e:
        print("Error:", e)
        raise RuntimeError(f"Failed to send verification email to {email}")
    validation_entry = Validation(user=user, verification_str=verificationKey)
    return render(request, "Williz/resetPasswordVerify.html", context)

def resetPasswordVerify(request):
    context = {}
    salt_chars = []
    verify = request.POST["verify"]
    NewPsw = request.POST["NewPassword"]
    ConfPsw = request.POST["ConfPassword"]
    for i in range(10):
        salt_chars.append(random.choice(ALPHABET))
    salt = "".join(salt_chars)
    pw_hashed = hashlib.sha256(str(ConfPsw + salt).encode('utf8')).hexdigest()

    print(request.session.get("resetID", None))
    if (((request.session.get("resetID", None))) == verify):
        print("Passed session")
        if (NewPsw == ConfPsw):
            print("Passed passwordConf")
            with transaction.atomic():
                user = User(pw_salt=salt,
                    pw_hash=pw_hashed)
                user.save()
                return HttpResponseRedirect("../login/")
        return HttpResponseRedirect(f"../register/?&status=pws_didnt_match")
    return HttpResponseRedirect(f"../resetPasswordVerify/?&status=Code_Expired")
# Adam's helper functions

# Carson's helper functions

# Dan's helper functions

# Mike's Views
def email_verification_page(request, verify_string=None):
    # TODO: Test this function and verification email by making a dummy verification page and dummy verif entries
    """
    Author: Mike
    View to present the user with either:
        1. Successful verification message
        2. Invalid or expired verification string message
    In the first case, the helper funciton verifying the user is called to verify their email.
    :param request:
    :return:
    """
    # Failed verify is the default
    context = {"message": "Ooops! We failed to verify your email."}
    if verify_string is not None:
        # Good case, still need to verify user tho
        try:
            val_entry = Validation.objects.get(verification_str=verify_string)
            if val_entry.expires <= datetime.datetime.now():
                return render(request, context={"message": "Ooops, that link has expired. Try requesting another."},
                              template_name="Williz/stub_verify_email.html")
            user_id = val_entry.user_id
            user = User.objects.get(pk=user_id)
            email = user.email
            context["message"] = f"Your email: {email} has been verified."
            context["name"] = user.f_name
            user.email_validation = True
            user.save()
            return render(request, context=context, template_name="Williz/stub_verify_email.html")
        except Validation.DoesNotExist:
            print(f"Invalid verification string {verify_string}")
            return render(request, context=context, template_name="Williz/stub_verify_email.html")
    # No verification string found, render with the message of failure
    else:
        return render(request, context=context, template_name="Williz/stub_verify_email.html")


def force_make_email_verification(request, email=None):
    """
    My somewhat hacky solution to generating email verifications while there is no
    account creation/verification request implemented.
    :param email:
    :return: None
    """
    create_email_verification(email)
    return HttpResponse(f"<h1>Made an email verification for {email}.</h1><p>Check email for link</p>")

# Zak's helper functions

"""
============================================= Helper Functions =========================================================
"""
# Adam's helper functions

# Carson's helper functions

# Dan's helper functions


# Mike's helper functions
@transaction.atomic
def create_email_verification(email):
    """
    Author: Mike
    Function which produces a random 45-char verificaiton string, generates a validation entry in the validation
    table. Finishes by sending an email to the user.
    :param email: an email address as a string
    :return: None
    """
    try:
        seed(time())
        veri_str = "".join(choices(URL_SAFE_CHARS, k=45))
        veri_link = f"{BASE_URL}/verify/email/{veri_str}"
        # Get the user's data from DB
        user = User.objects.get(email=email)
        first = user.f_name
        last = user.l_name
        user_type = CODE_TO_USER_TYPE[user.user_type]
        # Set the verification entry (atomic ensure only happens if email succeeds)
        validation_entry = Validation(user=user, verification_str=veri_str)
        # Send the verificaiton email
        send_verification_email(email, veri_link, user_type, first, last)
        validation_entry.save()
    except Exception as e:
        print(f"Exception while attempting to send a verificaiton email to {email}.")
        raise e


def send_verification_email(email, verification_link, user_type, f_name, l_name):
    """
    Author: Mike
    :param email: (str) an email address
    :param verification_link: (str) link to verify the email
    :param user_type: (str) Name for the type of user being verified
    :param f_name: (str) User's first name
    :param l_name: (str) User's last name
    :return: None
    """
    try:
        message = f"Greetings {f_name} {l_name},\n\n" + \
                    f"Congrats on creating your account as a {user_type}." + \
                    f"The following link to verify your email is valid for 10 minutes:\n\n" + \
                    f"{verification_link}\n" +\
                    f"\nIf you find this link has expired please submit another verification request from the login page."\
                    + f"\n\nRegards,\nThe Williz team"
        send_mail(
            "Williz Email Verification",
            message,
            "williznotifmail@gmail.com",
            [email],
            fail_silently=False
        )
    except Exception as e:
        print("Error:", e)
        raise RuntimeError(f"Failed to send verification email to {email}")


def generate_email_veri_str():
    """
    Author: Mike
    Helper func to generate a unique email verification string.
    :return: (str) unique 45 char verification string
    """
    seed(time())
    veri_str = "".join(choices(URL_SAFE_CHARS, k=45))
    colliding_entries = Validation.filter(verification_str=veri_str)
    # if by some miracle of randomness it exists... try again
    if len(colliding_entries) > 0:
        return generate_email_veri_str()
    return veri_str


def generate_reset_request_veri_str():
    """
    Author: Mike
    Helper func to generate a unique password reset verification string.
    :return: (str) unique 45 char verification string
    """
    seed(time())
    veri_str = "".join(choices(URL_SAFE_CHARS, k=45))
    colliding_entries = RequestReset.filter(verification_str=veri_str)
    # if by some miracle of randomness it exists... try again
    if len(colliding_entries) > 0:
        return generate_email_veri_str()
    return veri_str

# Zak's helper functions

