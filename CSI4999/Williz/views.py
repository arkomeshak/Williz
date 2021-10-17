import binascii
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
# HMAC imports
import hmac
from CSI4999.settings import SECRET_KEY
# Time and random imports
from random import choices, seed
import datetime
from time import time

"""
============================================= Constants & Globals ======================================================
"""

ASCII_PRINTABLE = "0123456789abcdefghIjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-=_+[]{}./<>?|`~ "
URL_SAFE_CHARS = "0123456789abcdefghIjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ–_"
BASE_URL = settings.BASE_URL  # Get the base URL from settings.py for use in email links
# If we needed to add a new user, and give it a code in the DB, we simply need to add to the below constant list
USER_TYPES = ("admin", "realtor", "appraiser", "lender")
CODE_TO_USER_TYPE = {user_code: user_type for user_code, user_type in enumerate(USER_TYPES)}
USER_TYPE_TO_CODE = {USER_TYPES[i]: i for i in range(len(USER_TYPES))}
STATES = ()  # TODO: make a const list of 2-letter state codes
SESSION_EXPIRATION = 1

# Brute force lockout values
FAILED_LOGINS_THRESHOLD = 5
LOCKOUT_DURATION_THRESHOLD = 60
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


def create_listing(request, email):
    user = User.objects.get(email=email)

    if user.user_type != 1:
        return HttpResponseRedirect(f"/profile/email/{email}?&status=access_denied")

    context = {
        'u_id': user.user_id
    }

    return render(request, "Williz/createListing.html", context)


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


####################################################################
########################### Adam's Views ###########################
####################################################################

def accountRequests(request):
    """
    UserRequests = User.objects.filter(verification_status=False)
    context["UserData"] = generate_user_requests(UserRequests)
    context["error"] = False
    """
    context = {}

    UserReqeustTable = User.objects.all().exclude(user_type=0)

    print(UserReqeustTable)
    #print(RATable)
    RATable = []
    for us in UserReqeustTable.iterator():
        if (User.objects.get(user_id=us.user_id).user_type == 1):
            RATable.append(Realtor.objects.get(user_id = us.user_id).lic_num)
        elif  (User.objects.get(user_id=us.user_id).user_type == 2):
            RATable.append(Appraiser.objects.get(user_id = us.user_id).lic_num)
        elif  (User.objects.get(user_id=us.user_id).user_type == 3):
            RATable.append("N/A")

    print("length", len(RATable))
    NewRARTable = []
    for i, user in enumerate(UserReqeustTable):
        if user.user_type == USER_TYPE_TO_CODE["realtor"]:
            entry = {"num": i + 1,"user_type": "realtor", "email": user.email, "f_name": user.f_name, "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id, "verification_status": user.verification_status}
            NewRARTable.append(entry)
        if user.user_type == USER_TYPE_TO_CODE["appraiser"]:
            entry = {"num": i + 1,"user_type": "Appraiser", "email": user.email, "f_name": user.f_name, "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id, "verification_status": user.verification_status}
            NewRARTable.append(entry)
        if user.user_type == USER_TYPE_TO_CODE["lender"]:
            entry = {"num": i + 1,"user_type": "Lender", "email": user.email, "f_name": user.f_name, "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id, "verification_status": user.verification_status}
            NewRARTable.append(entry)

    for i in NewRARTable:
        print(i)
    return render(request, 'Williz/accountRequests.html',{'UserRequests':NewRARTable})
      

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
        ForgotPassword = RequestReset(verification_str=verificationKey,
                                      user=user)
        ForgotPassword.save()

    RequestReset.objects.get(verification_str=verificationKey).verification_str


    request.session["email"] = email
    try:
        message = f"Greetings,\n\n" + \
                  f"The following code is to verify your email for a password reset valid for 10 minutes:\n\n" + \
                  f"{verificationKey}\n" + \
                  f"\nIf you find this link has expired please submit another verification request from the login page." \
                  + f"\n\nRegards,\nThe Williz team"
        send_mail(
            "Reset Password",
            message,
            "williznotifmail@gmail.com",
            [email],
            fail_silently=False
        )
    except Exception as e:
        print("Error:", e)
        raise RuntimeError(f"Failed to send verification email to {email}")
    validation_entry = Validation(user=user, verification_str=verificationKey)
    return HttpResponseRedirect(f"../password_reset/")


def resetPasswordVerify(request):
    context = {}
    salt_chars = []
    verify = request.POST.get("verify")
    NewPsw = request.POST.get("NewPassword")
    str(verify)
    str(NewPsw)
    print(NewPsw)
    print(request.session.get("email", None))
    ConfPsw = request.POST.get("ConfPassword")
    ConfPsw = str(ConfPsw)
    print(ConfPsw)
    for i in range(10):
        salt_chars.append(random.choice(ALPHABET))
    salt = "".join(salt_chars)
    str(salt)
    pw_hashed = hashlib.sha256(str(ConfPsw + salt).encode('utf8')).hexdigest()
    print(salt)
    print(pw_hashed)

    print(request.session.get("resetID", None))
    if (((request.session.get("resetID", None))) == verify):
        print("Passed session")
        if (NewPsw == ConfPsw):
            if not pw_validation(NewPsw):
                return HttpResponseRedirect(f"../password_reset/?&status=invalid_pw")
            print("Passed passwordConf")
            with transaction.atomic():
                PswChange = User.objects.get(email=request.session.get("email", None))
                PswChange.pw_salt = salt
                PswChange.pw_hash = pw_hashed
                PswChange.save()
                return HttpResponseRedirect("../login/")
        return HttpResponseRedirect(f"../password_reset/?&status=pws_didnt_match")
    return HttpResponseRedirect(f"../password_reset/?&status=Code_Expired")


# Carson's Views

def password_reset(request):
    context = {}
    return render(request, "Williz/resetPasswordVerify.html", context)


@transaction.atomic  # Carson
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
    if not pw_validation(pw):
        return HttpResponseRedirect(f"../register/?&status=pw_not_valid")
    salt_chars = []
    for i in range(10):
        salt_chars.append(random.choice(ALPHABET))
    salt = "".join(salt_chars)
    pw_hashed = hashlib.sha256(str(pw + salt).encode('utf8')).hexdigest()

    # gathers data
    utype = request.POST["radio"]
    utype = int(utype)
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
    create_email_verification(email_given)
    return HttpResponseRedirect("../login/")




@transaction.atomic  # Carson
def create_listing_handler(request):
    """
              Author: Carson
              Function which creates a new listing in the database based off info added in HTML form
              :return: redirects to login page
          """
    context = {}

    user = User.objects.get(user_id=int(request.POST['user_id'].replace('/', '')))

    if user.user_type != 1:
        return HttpResponseRedirect(f"/profile/email/{user.email}?&status=access_denied")

    h_num = request.POST["house_num"]
    street_given = request.POST["street"]
    city_given = request.POST["city"]
    state_given = request.POST["state"]
    zip_given = request.POST["zip"]
    h_size = request.POST["house_size"]
    p_size = request.POST["prop_size"]
    bed_num = request.POST["bed_num"]
    bath_num = request.POST["bath_num"]
    asking = request.POST["ask_price"]

    if request.POST['desc'] != "":
        desc = request.POST['desc']

        listing = Listing(house_num=h_num,
                          street_name=street_given,
                          city=city_given,
                          state=state_given,
                          zip_code=zip_given,
                          house_size=h_size,
                          property_size=p_size,
                          num_beds=bed_num,
                          num_baths=bath_num,
                          asking_price=asking,
                          realtor=user,
                          description=desc)
    else:
        listing = Listing(house_num=h_num,
                          street_name=street_given,
                          city=city_given,
                          state=state_given,
                          zip_code=zip_given,
                          house_size=h_size,
                          property_size=p_size,
                          num_beds=bed_num,
                          num_baths=bath_num,
                          asking_price=asking,
                          realtor=user)

    listing.save()
    return HttpResponseRedirect(f"/profile/email/{user.email}?&status=creation_success")


# Dan's Views
"""
   Author: Dan
   Function that handles login requests
"""
def login_handler(request):
    try:
        if request.method == 'POST':
            post = request.POST
            if "email" in post and "Psw" in post:
                email = post["email"]
                # Check to see if user is locked out. redirect to login if they are
                if is_locked_out(request, email):
                    return HttpResponseRedirect(f"/login?&status=account_lockout")
                dev_id = None
                if "device" in request.COOKIES:
                    dev_id = int(request.COOKIES["device"].split(",")[3])
                passwordAttempt = post["Psw"]
                try:
                    query = User.objects.get(email=email)
                except Exception:
                    raise ValueError("Email not found")
                if not query.email_validation:
                    return HttpResponseRedirect(f"/login?&status=Need_validation")
                # The password from the user
                # the salt from the database
                salt = query.pw_salt

                if query.pw_hash == "default":
                    return HttpResponseRedirect(f"/resetPassword")

                passwordGuess = hashlib.sha256(str(passwordAttempt + salt).encode('utf-8')).hexdigest()
                # the salted and hashed password from the database
                correctPwHash = (query.pw_hash)
                if (passwordGuess == correctPwHash):
                    # Make a new device cookie and delete one if it exists
                    digest, nonce = make_hmac_digest(SECRET_KEY, email)
                    new_cookie_str = digest.hex() + f",{nonce.hex()},{email},"  # Still need to get the cookie key
                    with transaction.atomic():
                        if dev_id is not None:
                            DeviceCookie.objects.get(pk=dev_id).delete()
                        new_dev_cookie = DeviceCookie(
                            user=query,
                            nonce=nonce,
                            signature=digest
                        )
                        new_dev_cookie.save()
                    # Now that we have the id tack it on to the cookie, and send the cookie in response
                    dev_id = str(new_dev_cookie.pk)
                    new_cookie_str += dev_id
                    # login success
                    # Set the uname session value to username the user logged in with
                    if (request.POST.get('remember') == 'on'):
                        print("remember?", request.POST.get('remember'))
                        request.session["email"] = email
                        request.session.set_expiry(
                            SESSION_EXPIRATION * 60)  # expires in SESSION_EXPIRATION * 60s seconds (Final Suggestion: if remember me is checked we can set session to last mabye 7 days)

                    else:
                        print("remember?", request.POST.get('remember'))
                        request.session["email"] = email
                        request.session.set_expiry(
                            SESSION_EXPIRATION * 30)  # expires in SESSION_EXPIRATION * 30s seconds (Final Suggestion: if remember me is unchecked we can set session to last 1 day)

                    u_type = query.user_type

                    if u_type == 0:
                        response = HttpResponseRedirect(f"/accountRequests?&status=Login_success")

                    else:
                        response = HttpResponseRedirect(f"/profile/email/{email}?&status=Login_success")

                    response.set_cookie("device", new_cookie_str)

                    return response
                else:  # Case of failed login should add a failed attempt
                    if "device" in request.COOKIES:
                        print("device cookie set")
                        if verify_device_cookie(request.COOKIES["device"]):
                            print("and cookie is valid")
                            record_failed_device_attempt(dev_id)
                    else:
                        record_failed_untrusted_attempt(email)
                    messages.error(request, 'Email or password not correct')
                    return HttpResponseRedirect(f"/login?&status=Login_Failed")
            else:
                return HttpResponseRedirect(f"/login?&status=not_valid")
        else:
            return HttpResponseRedirect(f"/login?&status=rediect_not_post")
    except ValueError as e:
        print(e)
        raise e
        return HttpResponseRedirect(f"/login?&status=Account_Not_Found")
    except Exception as e:
        print(f"Exception while attempting login: {e}")
        raise e
        return HttpResponseRedirect(f"/login?&status=server_error")

    """
           Author: Dan
           Function that gets called on the accountRequests page when user clicks the Delete button
           
           Deletes user account from the database
       """
def delete_user_account(request, user_id):
    try:
        user = User.objects.get(user_id=user_id)
        user.delete()
        messages.success(request, "The user has been deleted.")
    except Exception as e:
        print("e", e)
    return render(request, template_name="Williz/accountRequests.html")

  
# Mike's Views
def email_verification_page(request, verify_string=None):
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
        with transaction.atomic():
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
                return render(request, context=context, template_name="Williz/stub_verify_email.html")
            except Validation.DoesNotExist:
                print(f"Invalid verification string {verify_string}")
                return render(request, context=context, template_name="Williz/stub_verify_email.html")
            # No verification string found, render with the message of failure

    return render(request, contex=context, template_name="Williz/stub_verify_email.html")


def handler404(request, *args, **argv):
    """
    A 404 handler which directs to the 404 page.
    :param request: http request
    :return: None
    """
    return render("<div><h1>That resource was not found</h1></div>")


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
    return HttpResponseRedirect("Williz/login")


def change_verification(request, email):
    """
        Author: Zak
        Function which allows admin to change status of license validation for all user types
        :return: redirect to current page with updated info
    """
    user = User.objects.get(email=email)
    user.verification_status = not user.verification_status
    user.save()
    response = HttpResponseRedirect(f"/accountRequests")
    return response

"""
============================================= Helper Functions =========================================================
"""


# Adam's helper functions

# Carson's helper functions
def pw_validation(pw):
    """
        Author: Carson
        Function which accepts the input of a password string that confirms that it does or does not conform to the
        standards set forth (namely length and contents)
        :return: true or false
    """

    if len(pw) < 8:
        return False

    num_lower = 0
    num_upper = 0
    num_digits = 0

    for char in pw:
        if char.isdigit():
            num_digits += 1
        elif char.isupper():
            num_upper += 1
        elif char.islower():
            num_lower += 1
        else:
            pass

    print(num_digits)
    print(num_upper)
    print(num_lower)
    if num_lower == 0:
        return False
    elif num_upper == 0:
        return False
    elif num_digits == 0:
        return False
    else:
        return True


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
        with transaction.atomic():
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
                  f"{verification_link}\n" + \
                  f"\nIf you find this link has expired please submit another verification request from the login page." \
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


def verify_session(request):
    """
    Author: Mike
    Verifies the user session is still valid.
    :param request: http request
    :return: boolean
    """
    return "sessionid" in request.COOKIES and request.session.get_expiry_age() != 0


def user_is_expected_type(expected_type, usr_id=None, email=None):
    """
    Author: Mike
    Returns whether the user is registered in the database as the type passed in as the expected_type string.
    Works with at least one of user_id or email.
    :param expected_type_type: string
    :param usr_id: int
    :param email: string
    :return: boolean
    """
    global USER_TYPES, USER_TYPE_TO_CODE
    # Check for and raise some easy exceptions b4 costly DB lookup
    if usr_id is None and email is None:
        raise ValueError("At least one of usr_id or email parameters must be provided.")
    elif expected_type not in USER_TYPES:
        raise ValueError(f"{expected_type} is not a known user type.")
    try:
        if usr_id is not None:
            user = User.objects.get(pk=usr_id)
        else:
            user = User.objects.get(email=email)
    except User.DoesNotExist as e:
        print(f"Couldn't find a user with email or id: {usr_id if usr_id is not None else email}.")
        raise RuntimeError(e)
    return USER_TYPE_TO_CODE[expected_type] == user.user_type


def verify_device_cookie(cookie):
    """
    Author: Mike
    Function which verifies a device cookie
    :return:
    """
    # Cookie is too short to be valid
    if len(cookie) <= 128:
        return False
    try:
        hmac_received, nonce_received, email, dev_id = cookie.split(",")
        print("cookie given to us")
        for thing in (hmac_received, nonce_received, email, dev_id ):
            print(thing)
        if dev_id.isnumeric() and int(dev_id) >= 0:
            print("id is valid integer")
            dev_pk = int(dev_id)
            user_id = User.objects.get(email=email).user_id
            dev_cookie = DeviceCookie.objects.get(pk=dev_pk)
            if int(dev_cookie.user.pk) != user_id:
                print("cookie ID does not match user ID for actual user")
                return False  # Cookie is for the wrong user
            print("problem is verifying the digest")
            nonce = dev_cookie.nonce
            return verify_hmac_hex_digest(skey=SECRET_KEY, email=email, nonce=nonce, hmac_hex_received= hmac_received)
        else:
            print("cookie had an invalid ID")
            return False  # invalid device cookie ID provided
    except Exception as e:
        print(f"Error validating cookie\n {cookie}\n{e}")
        raise e
    return False


@transaction.atomic
def is_locked_out(request, email):
    """
    Author: Mike
    Function which returns whether the user is locked out or not. This is done by checking device lockouts if a
    device cookie is present, or untrusted lockouts if no device cookie is present.
    :param request: HTTP request
    :param user_id: int
    :return: boolean
    """
    try:
        user_id = User.objects.get(email=email)
        if "device" in request.COOKIES:
            sent_dev_cookie = request.COOKIES["device"]
            # If valid cookie was sent, check if user is locked out
            if verify_device_cookie(sent_dev_cookie):
                print(f"I verified the cookie!")
                dev_id = sent_dev_cookie[128:].split(",")[3]
                dev_pk = int(dev_id)
                now = timezone.now()
                with transaction.atomic():
                    for lockout in DeviceLockout.objects.filter(device_cookie=dev_pk):
                        if lockout.lock_exp > now:
                            return True
                        lockout.delete()  # While we're here let's delete expired lockouts
            # Invalid cookie locks out if there is an untrusted lockout for the user's account
            else:
                print(f"I'm is_locked_out and I didn't trust this cookie\n{sent_dev_cookie}")
                untrusted_lockouts = UntrustedLockout.objects.filter(pk=user_id)
                if len(untrusted_lockouts) == 1:
                    return True
        else:
            untrusted_lockouts = UntrustedLockout.objects.filter(pk=user_id)
            if len(untrusted_lockouts) == 1:
                return True
    # Don't trust sus device cookies which caused an error to be raisins
    except User.DoesNotExist as e:
        print(f"No user found for email {email}")
        return True
    except DeviceCookie.DoesNotExist as e:
        bad_id = request.COOKIES["device"].split(",")[3]
        print(f"No device cookie with the id={bad_id} found")
        return True
    except Exception as e:
        print(f"Device cookie {sent_dev_cookie} caused exception:\n\t{e}")
        #return True
        raise e
    return False


@transaction.atomic
def record_failed_untrusted_attempt(email):
    """
    Author: Mike
    Function which adds a failed attempt from an unstrusted device. Sets an untrusted lockout if
    attempts from ALL devices within LOCKED_DURATION_THRESHOLD is greater than FAILED_LOGINS_THRESHOLD.
    :param email: string
    :return: None
    """
    global FAILED_LOGINS_THRESHOLD, LOCKOUT_DURATION_THRESHOLD
    try:
        user = User.objects.get(email=email)
        user_pk = user.pk
        attempt = FailedLoginAttempt(
            user=user,
            device_cookie=None
        )
        attempt.save()
        time_window = timezone.now() - datetime.timedelta(minutes=LOCKOUT_DURATION_THRESHOLD)
        # If too many failed logins have happened, set an untrusted lockout
        if len(FailedLoginAttempt.objects.filter(user=user_pk).filter(when__gte=time_window)) >= FAILED_LOGINS_THRESHOLD:
            u_lockout = UntrustedLockout(
                user_id=user,
                lock_exp=timezone.now() + datetime.timedelta(minutes=LOCKOUT_DURATION_THRESHOLD)
            )
            u_lockout.save()
    except User.DoesNotExist as e:
        print(f"Failed to register a failed login. User with email {email} does not exist.")
    except Exception as e:
        print(f"Uncaught exception while attempting to add a failed login attempt for user with email {email}.")
        raise e


def record_failed_device_attempt(dev_pk):
    """
    Author: Mike
    Function which adds a failed attempt from an specific device. Sets a device lockout if
    attempts from the device within LOCKED_DURATION_THRESHOLD is greater than FAILED_LOGINS_THRESHOLD.
    :param dev_pk: int
    :return: None
    """
    global FAILED_LOGINS_THRESHOLD, LOCKOUT_DURATION_THRESHOLD
    try:
        device = DeviceCookie.objects.get(pk=dev_pk)
        user = User.objects.get(pk=device.user.pk)
        user_pk = user.user_id
        attempt = FailedLoginAttempt(
            user=user,
            device_cookie=device
        )
        attempt.save()
        time_window = timezone.now() - datetime.timedelta(minutes=LOCKOUT_DURATION_THRESHOLD)
        # If too many failed logins have happened on this device, set a device lockout
        if len(FailedLoginAttempt.objects.filter(user=user_pk)
                       .filter(device_cookie=dev_pk)
                       .filter(when__gte=time_window)) >= FAILED_LOGINS_THRESHOLD:
            dev_lockout = DeviceLockout(
                lock_exp=timezone.now() + datetime.timedelta(minutes=LOCKOUT_DURATION_THRESHOLD),
                device_cookie=device
            )
            dev_lockout.save()
    except User.DoesNotExist as e:
        print(f"Failed to register a failed login. User with id {device.user} does not exist.")
        raise RuntimeError(e)
    except DeviceCookie.DoesNotExist as e:
        print(f"Failed to register a failed login. Device cookie with id {dev_pk} does not exist.")
        raise RuntimeError(e)
    except Exception as e:
        print(f"Uncaught exception while attempting to add a failed login attempt for device with id={dev_pk}.")
        raise RuntimeError(e)


def make_hmac_digest(skey, email):
    """
    Author: Mike
    Function which takes secret key and email strings, returns a pair (sha3-512-hmac(secret key, email+nonce), nonce)
    :param skey: string
    :param email: string
    :return: (bytes, bytes)
    """
    seed(time())
    # Nonce used as salt added to end of email
    nonce = bytes("".join(choices(ASCII_PRINTABLE, k=128)), encoding="ascii")
    message = bytes(email, encoding="ascii") + nonce
    generated_hmac = hmac.new(key=bytes(skey, encoding="ascii"), msg=message, digestmod="sha3_512")
    digest = generated_hmac.digest()
    # Sanity check: Nonce should be 128 bytes, hmac digest should be 64
    assert len(nonce) == 128 and len(digest) == 64
    return digest, nonce


def verify_hmac_hex_digest(skey, email, nonce, hmac_hex_received):
    """
    Author: Mike
    Function which takes in secret key, email strings, a nonce in the form of bytes, and a hmac in the form of a hex
    string. Returns true if the hmac hex sent matches that computed from the secret key, email, and nonce. Assumes
    a sha3-512-hmac.
    :param skey: string
    :param email: string
    :param nonce: bytes
    :param hmac_hex_received: string
    :return: boolean
    """
    message = bytes(email, "ascii") + nonce
    generated_hmac = hmac.new(key=bytes(skey, encoding="ascii"), msg=message, digestmod="sha3_512")
    return generated_hmac.hexdigest() == hmac_hex_received

# Zak's helper functions
# ...*tumble weed blows in wind*
