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
SESSION_EXPIRATION = 1


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


def profile(request, email):
    """
        Author: Zak
        Function which loads user data into html page to allow user to edit their information
        :param email: user email associated with account
        :return: render of profile.html with new information
    """
    user = User.objects.get(email=email)
    if user.user_type == 1:
        realtor = Realtor.objects.get(user_id=user.user_id)
        context = {
            'user_id': user.user_id,
            'f_name': user.f_name,
            'l_name': user.l_name,
            'email': user.email,
            'state': realtor.lic_state,
            'license_num': realtor.lic_num,
            'bank': 'N/A'
        }
    elif user.user_type == 2:
        appraiser = Appraiser.objects.get(user_id=user.user_id)
        context = {
            'user_id': user.user_id,
            'f_name': user.f_name,
            'l_name': user.l_name,
            'email': user.email,
            'state': appraiser.lic_state,
            'license_num': appraiser.lic_num,
            'bank': 'N/A'
        }
    elif user.user_type == 3:
        lender = Lender.objects.get(user_id=user.user_id)
        context = {
            'user_id': user.user_id,
            'f_name': user.f_name,
            'l_name': user.l_name,
            'email': user.email,
            'state': 'N/A',
            'license_num': 'N/A',
            'bank': lender.mortgage_co
        }
    return render(request, 'Williz/profile.html', context)

# Adam's helper functions

# Carson's Views
@transaction.atomic #Carson
def register_user_handler(request):
    """
           Author: Carson
           Function which creates a new user in the database based off info added in HTML form
           :return: redirects to login page
       """
    context = {}

    # checks if pws match, creates salt and hash
    pw = request.POST["Psw"]
    pw_conf = request.POST["ConfPsw"]
    if pw != pw_conf:
        messages.error(request, 'Make sure your password fields match')
        return HttpResponseRedirect(f"../register/?&status=pws_didnt_match")
    salt_chars = []
    for i in range(10):
        salt_chars.append(random.choice(ALPHABET))
    salt = "".join(salt_chars)
    pw_hashed = hashlib.sha256(str(pw + salt).encode('utf8')).hexdigest()

    # gathers data
    utype = request.POST["radio"]
    utype = int(utype)
    print(utype)
    name1 = request.POST["fname"]
    name2 = request.POST["lname"]
    email_given = request.POST["email"]

    with transaction.atomic():  # ensures atomicity of db commit
        user = User(f_name=name1,
                    l_name=name2,
                    pw_salt=salt,
                    pw_hash=pw_hashed,
                    email=email_given,
                    user_type=utype)
        user.save()  # adds user to user table
        u_id = User.objects.last()  # gets user created above

        if utype == 1:  # if user is a realtor
            lic = request.POST["License"]
            origin = request.POST["state"]
            realtor = Realtor(user_id=u_id,
                              lic_state=origin,
                              lic_num=lic)
            realtor.save()  # save additional info to realtor table

        elif utype == 2:  # if user is an appraiser
            lic = request.POST["License"]
            origin = request.POST["state"]
            appraiser = Appraiser(user_id=u_id,
                                  lic_state=origin,
                                  lic_num=lic)
            appraiser.save()  # save additional info to appraiser table

        elif utype == 3:
            ml_name = request.POST["Company"]
            company = MortgageCo(co_name=ml_name)
            company.save()  # create company in company table
            co_id = MortgageCo.objects.last()
            lender = Lender(user_id=u_id,
                            mortgage_co=co_id)
            lender.save()  # save additional info to lender table

    return HttpResponseRedirect("../login/")

# Dan's Views
def login_handler(request):
    try:
        if request.method == 'POST':
            post = request.POST
            if "email" in post and "Psw" in post:
                email = post["email"]
                passwordAttempt = post["Psw"]
                try:
                    query = User.objects.get(email=email)
                except Exception:
                    raise ValueError("Email not found")
                if not query.emailvalidation:
                    return HttpResponseRedirect(f"/login?&status=Need_validation")
                # The password from the user
                # the salt from the database
                salt = query.pw_salt
                print("salt", salt)
                passwordGuess = hashlib.sha256(str(passwordAttempt + salt).encode('utf-8')).hexdigest()
                # the salted and hashed password from the database
                correctPwHash = (query.pw_hash)
                print("correct:", correctPwHash)
                print("correct:", correctPwHash, "   GUESS: ", passwordGuess)
                if (passwordGuess == correctPwHash):
                    # login success
                    # Set the uname session value to username the user logged in with
                    if (request.POST.get('remember') == 'on'):
                        print(request.POST.get('remember'))

                        request.session["email"] = email
                        request.session.set_expiry(
                            SESSION_EXPIRATION * 60)  # expires in SESSION_EXPIRATION * 60s seconds (Final Suggestion: if remember me is checked we can set session to last mabye 7 days)

                    else:
                        print(request.POST.get('remember'))
                        request.session["email"] = email
                        request.session.set_expiry(
                            SESSION_EXPIRATION * 30)  # expires in SESSION_EXPIRATION * 30s seconds (Final Suggestion: if remember me is unchecked we can set session to last 1 day)
                    response = HttpResponseRedirect(f"/profile/email/{email}/&status=Login_success")
                    return response
                else:
                    messages.error(request, 'Email or password not correct')
                    return HttpResponseRedirect(f"/login?&status=Login_Failed")
            else:
                return HttpResponseRedirect(f"/login?&status=not_valid")
        else:
            return HttpResponseRedirect(f"/login?&status=rediect_not_post")
    except ValueError:
        return HttpResponseRedirect(f"/login?&status=Account_Not_Found")
    except Exception as e:
        print(e)
        return HttpResponseRedirect(f"/login?&status=server_error")

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
            now = timezone.now()
            expires = val_entry.expires
            print("now is ", now)
            print("expires in ", expires)
            if val_entry.expires <= timezone.now():
                return render(request, context={"message": "Ooops, that link has expired. Try requesting another."},
                              template_name="Williz/stub_verify_email.html")
            user_id = val_entry.user_id
            user = User.objects.get(pk=user_id)
            email = user.email
            context["message"] = f"Your email: {email} has been verified."
            context["name"] = user.f_name
            user.email_validation = True
            user.save()
            val_entry.delete()
            val_entry.save()
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

# Zak's Views

def edit_user_info(request):
    """
        Author: Zak
        Function which loads user data from html page into database to allow user to edit their information
        :return: render of login.html
    """
    user = User.objects.get(user_id=int(request.POST['user_id'].replace('/', '')))
    if user.user_type == 1:
        realtor = Realtor.objects.get(user_id=user.user_id)
        if request.POST['fnameInput'] != "":
            user.f_name = request.POST['fnameInput']
        if request.POST['lnameInput'] != "":
            user.l_name = request.POST['lnameInput']
        if user.email != request.POST['emailInput'] and request.POST['emailInput'] != "":
            user.email = request.POST['emailInput']
            create_email_verification(user.email)
        if request.POST['state'] != "" and request.POST['state'] != "Please Select":
            realtor.lic_state = request.POST['state']
        if request.POST['LicenseInput'] != "":
            realtor.lic_number = request.POST['LicenseInput']
        user.save()
        realtor.save()
    elif user.user_type == 2:
        appraiser = Appraiser.objects.get(user_id=user.user_id)
        if request.POST['fnameInput'] != "":
            user.f_name = request.POST['fnameInput']
        if request.POST['lnameInput'] != "":
            user.l_name = request.POST['lnameInput']
        if user.email != request.POST['emailInput'] and request.POST['emailInput'] != "":
            user.email = request.POST['emailInput']
        if request.POST['state'] != "" and request.POST['state'] != "Please Select":
            appraiser.lic_state = request.POST['state']
        if request.POST['LicenseInput'] != "":
            appraiser.lic_number = request.POST['LicenseInput']
        user.save()
        appraiser.save()
    elif user.user_type == 3:
        lender = Lender.objects.get(user_id=user.user_id)
        if request.POST['fnameInput'] != "":
            user.f_name = request.POST['fnameInput']
        if request.POST['lnameInput'] != "":
            user.l_name = request.POST['lnameInput']
        if user.email != request.POST['emailInput'] and request.POST['emailInput'] != "":
            user.email = request.POST['emailInput']
        if request.POST['CompanyInput'] != "":
            lender.mortgage_co = request.POST['CompanyInput']
        user.save()
        lender.save()
    return render(request, "Williz/login.html", context={})

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

