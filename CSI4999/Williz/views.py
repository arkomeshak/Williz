import binascii
import hashlib
import os
import random
import os

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
from os import listdir
from os.path import join, isdir
from io import *
from cryptography.fernet import Fernet


"""
============================================= Constants & Globals ======================================================
"""
ROOT_FILES_DIR = "Files/"
ASCII_PRINTABLE = "0123456789abcdefghIjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-=_+[]{}./<>?|`~ "
URL_SAFE_CHARS = "0123456789abcdefghIjklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ–_"
BASE_URL = settings.BASE_URL  # Get the base URL from settings.py for use in email links
# If we needed to add a new user, and give it a code in the DB, we simply need to add to the below constant list
USER_TYPES = ("admin", "realtor", "appraiser", "lender")
CODE_TO_USER_TYPE = {user_code: user_type for user_code, user_type in enumerate(USER_TYPES)}
USER_TYPE_TO_CODE = {USER_TYPES[i]: i for i in range(len(USER_TYPES))}
STATES = ()  # TODO: make a const list of 2-letter state codes
SESSION_EXPIRATION = 300  # Sessions last 300 seconds
# Brute force lockout values
FAILED_LOGINS_THRESHOLD = 5
LOCKOUT_DURATION_THRESHOLD = 60
ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
STATE_NAMES= {
    "Alabama": "AL",
    "Alaska": "AK",
    "Arizona": "AZ",
    "Arkansas": "AR",
    "California": "CA",
    "Colorado": "CO",
    "Connecticut": "CT",
    "Delaware": "DE",
    "Florida": "FL",
    "Georgia": "GA",
    "Hawaii": "HI",
    "Idaho": "ID",
    "Illinois": "IL",
    "Indiana": "IN",
    "Iowa": "IA",
    "Kansas": "KS",
    "Kentucky": "KY",
    "Louisiana": "LA",
    "Maine": "ME",
    "Maryland": "MD",
    "Massachusetts": "MA",
    "Michigan": "MI",
    "Minnesota": "MN",
    "Mississippi": "MS",
    "Missouri": "MO",
    "Montana": "MT",
    "Nebraska": "NE",
    "Nevada": "NV",
    "New Hampshire": "NH",
    "New Jersey": "NJ",
    "New Mexico": "NM",
    "New York": "NY",
    "North Carolina": "NC",
    "North Dakota": "ND",
    "Ohio": "OH",
    "Oklahoma": "OK",
    "Oregon": "OR",
    "Pennsylvania": "PA",
    "Rhode Island": "RI",
    "South Carolina": "SC",
    "South Dakota": "SD",
    "Tennessee": "TN",
    "Texas": "TX",
    "Utah": "UT",
    "Vermont": "VT",
    "Virginia": "VA",
    "Washington": "WA",
    "West Virginia": "WV",
    "Wisconsin": "WI",
    "Wyoming": "WY",
    "District of Columbia": "DC",
    "American Samoa": "AS",
    "Guam": "GU",
    "Northern Mariana Islands": "MP",
    "Puerto Rico": "PR",
    "United States Minor Outlying Islands": "UM",
    "U.S. Virgin Islands": "VI",
}


# Create your views here.


def index(request):
    return HttpResponse("<h1>Hello Williz!</h1>")


def login(request):
    context = {}
    return render(request, "Williz/login.html", context)


def register(request):
    context = {
        "states": [{"stat": k, "abbr": v} for k, v in STATE_NAMES.items()]
            }
    return render(request, "Williz/register.html", context)


def create_listing(request, email):
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")
    user = User.objects.get(email=email)
    if CODE_TO_USER_TYPE[user.user_type] != "realtor":
        return HttpResponseRedirect(f"/profile/email/{email}?&status=access_denied")

    context = {
        'u_id': user.user_id,
        "states": [{"stat": k, "abbr": v} for k, v in STATE_NAMES.items()]
    }

    return render(request, "Williz/createListing.html", context)


def profile(request, email):
    """
        Author: Zak
        Function which loads user data into html page to allow user to edit their information
        :param email: user email associated with account
        :return: render of profile.html with new information
    """
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")
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
            'bank': 'N/A',
            "states": [{"stat": k, "abbr": v} for k, v in STATE_NAMES.items()]
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
            'bank': 'N/A',
            "states": [{"stat": k, "abbr": v} for k, v in STATE_NAMES.items()]
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
            'bank': lender.mortgage_co,
            "states": [{"stat": k, "abbr": v} for k, v in STATE_NAMES.items()]
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
    # print(RATable)
    RATable = []
    for us in UserReqeustTable.iterator():
        if (User.objects.get(user_id=us.user_id).user_type == 1):
            RATable.append(Realtor.objects.get(user_id=us.user_id).lic_num)
        elif (User.objects.get(user_id=us.user_id).user_type == 2):
            RATable.append(Appraiser.objects.get(user_id=us.user_id).lic_num)
        elif (User.objects.get(user_id=us.user_id).user_type == 3):
            RATable.append("N/A")

    print("length", len(RATable))
    NewRARTable = []
    for i, user in enumerate(UserReqeustTable):
        if user.user_type == USER_TYPE_TO_CODE["realtor"]:
            entry = {"num": i + 1, "user_type": "realtor", "email": user.email, "f_name": user.f_name,
                     "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id,
                     "verification_status": user.verification_status}
            NewRARTable.append(entry)
        if user.user_type == USER_TYPE_TO_CODE["appraiser"]:
            entry = {"num": i + 1, "user_type": "Appraiser", "email": user.email, "f_name": user.f_name,
                     "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id,
                     "verification_status": user.verification_status}
            NewRARTable.append(entry)
        if user.user_type == USER_TYPE_TO_CODE["lender"]:
            entry = {"num": i + 1, "user_type": "Lender", "email": user.email, "f_name": user.f_name,
                     "l_name": user.l_name, "Lic_num": RATable[i], "user_id": user.user_id,
                     "verification_status": user.verification_status}
            NewRARTable.append(entry)

    for i in NewRARTable:
        print(i)
    return render(request, 'Williz/accountRequests.html', {'UserRequests': NewRARTable})


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


def searchListings(request):
    listings = []
    listingsQ = Listing.objects.all()

    print(listings)

    for i, List in enumerate(listingsQ):
        entry = {"house_num": List.house_num,
                 "street_name": List.street_name,
                 "state": List.state,
                 "asking_price": List.asking_price,
                 "city": List.city,
                 "zip_code": List.zip_code, }
        listings.append(entry)
        print(listings)

    return render(request, "Williz/searchListings.html", {'AllListings': listings})


def searchListings_handler(request):
    listings = []
    listingsQ = Listing.objects.all()

    print(listings)

    for i, List in enumerate(listingsQ):
        entry = {"house_num": List.house_num,
                 "street_name": List.street_name,
                 "state": List.state,
                 "asking_price": List.asking_price,
                 "city": List.city,
                 "zip_code": List.zip_code, }
        listings.append(entry)
        print(listings)
    userLocation = request.POST["userLoc"]
    return render(request, "Williz/searchListings.html", {'UserLoc': userLocation, 'AllListings': listings})

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

    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")
    user = User.objects.get(user_id=int(request.POST['user_id'].replace('/', '')))
    if CODE_TO_USER_TYPE[u_type] != "realtor":
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


def listing_image_upload(request, **kwargs):
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")

    # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
    listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
        .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
        .filter(city=kwargs["city"].replace("_", " ").strip()) \
        .filter(state=kwargs["state"].replace("_", " ").strip()) \
        .filter(zip_code=int(kwargs["zip"]))
    listing = listing_set[0]

    ctx = {
            "street": listing.street_name.replace(" ", "_"),
            "house_num": listing.house_num,
            "city": listing.city.replace(" ", "_"),
            "state": listing.state,
            "zip": listing.zip_code,
        }

    print(ctx)

    return render(request, context=ctx, template_name="Williz/listing_image_upload.html")


def listing_image_handler(request, **kwargs):
    """
                  Author: Carson
                  Function which uploads an image to the server for the purpose of being used in a listing
                  :return:
              """

    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")

    # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
    listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
        .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
        .filter(city=kwargs["city"].replace("_", " ").strip()) \
        .filter(state=kwargs["state"].replace("_", " ").strip()) \
        .filter(zip_code=int(kwargs["zip"]))
    listing = listing_set[0]

    if request.method != 'POST':
        print("Method", request.method)
        return HttpResponseRedirect("../?&status=invalid_upload_method")

    if "images" not in request.FILES:
        return HttpResponseRedirect("../?&status=missing_images")

    images = request.FILES.getlist('images')
    listing_id = listing.pk
    count = listing.image_count

    for image in images:
        count = count + 1
        file_type = image.name.split(".")[-1]
        assert file_type.lower() in ("jpg", "png", "jpeg")
        file_writer(image.read(), f"Listings/{listing_id}/", f"Listing{listing_id}_img{count}.{file_type}")

    listing.image_count = count
    listing.save()

    return HttpResponseRedirect(f"/listing/{kwargs['state']}/{kwargs['zip']}/{kwargs['city']}/{kwargs['street']}/{kwargs['house_num']}")


def appraisal_image_upload(request, **kwargs):
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")

    # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
    listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
        .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
        .filter(city=kwargs["city"].replace("_", " ").strip()) \
        .filter(state=kwargs["state"].replace("_", " ").strip()) \
        .filter(zip_code=int(kwargs["zip"]))
    listing = listing_set[0]

    return render(request, "Williz/appraisal_image_upload.html")


def appraisal_image_handler(request, **kwargs):
    """
                  Author: Carson
                  Function which uploads an image to the server for the purpose of being used in an appraisal
                  :return:
              """

    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")

    # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
    listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
        .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
        .filter(city=kwargs["city"].replace("_", " ").strip()) \
        .filter(state=kwargs["state"].replace("_", " ").strip()) \
        .filter(zip_code=int(kwargs["zip"]))
    listing = listing_set[0]

    if request.method != 'POST':
        print("Method", request.method)
        return HttpResponseRedirect("../?&status=invalid_upload_method")

    if "images" not in request.FILES:
        return HttpResponseRedirect("../?&status=missing_images")

    images = request.FILES.getlist('images')
    app_id = 1  # TODO: Add logic for app id
    count = 0

    for image in images:
        count = count + 1
        file_type = image.name.split(".")[-1]
        assert file_type.lower() in ("jpg", "png", "jpeg")
        file_writer(image.read(), f"Appraisals/{app_id}/images", f"Appraisal{app_id}_img{count}.{file_type}")

    return HttpResponseRedirect("../searchListings")


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
                    # Set the uname session value to username the user logged in with, and an expiration time
                    request.session["email"] = email
                    request.session["expires"] = timezone.now() + timedelta(seconds=SESSION_EXPIRATION)
                    # Admins redirect to a different page on login
                    u_type = query.user_type
                    if u_type == USER_TYPE_TO_CODE["admin"]:
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
    response = render(request, template_name="Williz/accountRequests.html")
    response.delete_cookie("device")  # Delete the device cookie so diff users can still login from this device
    return response


# Mike's Views
def set_appraiser_handler(request, **kwargs):
    """
    Author: Mike
    :param request:
    :return:
    """
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")
    try:
        if request.method != "POST":
            return HttpResponseRedirect(f"/?&status=invalid_method")
        elif "appraiser" not in request.POST:
            return HttpResponseRedirect(f"/?&status=no_appraiser_set")
        app_email = request.POST["appraiser"]
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        # Set appraiser
        assert len(listing_set) == 1
        listing = listing_set[0]
        user = User.objects.get(email=app_email)
        listing.appraiser = Appraiser.objects.get(pk=user)
        listing.save()
    except Exception as e:
        print(e)
        return HttpResponseRedirect(f"/?&status=no_appraiser_set")
    return HttpResponseRedirect(f"/listing/update/appraiser/{kwargs['state']}/{kwargs['zip']}/{kwargs['city']}/{kwargs['street']}/{kwargs['house_num']}")


def set_appraiser(request, **kwargs):
    """
    Author: Mike
    View to render a page used to set an  for a listing.
    :param request:
    :param kwargs:
    :return:
    """
    try:
        # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        if len(listing_set) != 1:  # Should get us one unique listing
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        if listing.appraiser is not None:
            appraiser = listing.appraiser
            user = User.objects.get(pk=appraiser.user_id.pk)
            context = {
                "f_name": user.f_name,
                "l_name": user.l_name,
                "email": user.email,
                "has_appraiser": True
            }
        else:
            context = {
                "f_name": "Dan",
                "l_name": "Dannerson",
                "email": "JeremyBuxioJulioValazII@aol.com",
                "has_appraiser": False
            }
        # Add the appraisers
        appraiser_set = User.objects.filter(user_type=USER_TYPE_TO_CODE["appraiser"])
        appraisers = [{"fname": app.f_name.capitalize(), "lname": app.l_name.capitalize(), "email": app.email} for app in appraiser_set]
        context["appraisers"] = appraisers
        context.update({
            "street": listing.street_name.replace(" ", "_"),
            "house_num": listing.house_num,
            "city": listing.city.replace(" ", "_"),
            "state": listing.state,
            "zip": listing.zip_code,
        })
        return render(request, context=context, template_name="Williz/set_appraiser.html")
    except Exception as e:
        print(e)



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
                    return render(request,
                                  context={"message": "Ooops, that link has expired. Try requesting another.", },
                                  template_name="Williz/verify_email.html")
                user_id = val_entry.user_id
                user = User.objects.get(pk=user_id)
                email = user.email
                context["message"] = f"Your email: {email} has been verified."
                context["name"] = user.f_name
                context["success"] = True
                user.email_validation = True
                user.save()
                val_entry.delete()
                return render(request, context=context, template_name="Williz/verify_email.html")
            except Validation.DoesNotExist:
                print(f"Invalid verification string {verify_string}")
                return render(request, context=context, template_name="Williz/verify_email.html")
            # No verification string found, render with the message of failure
    return render(request, context=context, template_name="Williz/verify_email.html")


def listing(request, **kwargs):
    """
    Author: Mike
    Function to render a real estate listing and send in a HTTP response.
    :param request: HTTP GET request
    :param kwargs: street name, street number, city, state, zip code
    :return: HTTP response
    """
    isCreator = False
    isLender = False
    isAppraiser = False
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in kwargs
    # Try to find the listing and build context
    try:
        # This looks bad, but filters are lazy, so actually only runs 1 big query with a gnarly where statement
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        if len(listing_set) != 1:  # Should get us one unique listing
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        # This is best practice

        email = request.session["email"]
        user = User.objects.get(email=email)

        if "email" in request.session and request.session["email"] == User.objects.get(
                user_id=listing.realtor.user_id).email:
            isCreator = True
        elif listing.lender is not None and ("lender" == CODE_TO_USER_TYPE[user.user_type] and Lender.objects.get(pk=user.pk).mortgage_co == listing.lender):
            isLender = True
        elif listing.appraiser is not None and ("appraiser" == CODE_TO_USER_TYPE[user.user_type] and Appraiser.objects.get(
                    user_id=user.pk) == listing.appraiser):
            apps = Appraisal.objects.filter(listing=listing).filter(appraiser=listing.appraiser)
            print("asdfgasdfgasdgfasgasfasdfasgasgsafsadfasgasfsadfasdfgasgfasgasdgfsadfsagfsag ", len(apps))
            if len(apps) == 0:
                isAppraiser = True
            elif not apps[0].is_complete:
                isAppraiser = True
            else:
                isAppraiser = False
        context = {
            "street": listing.street_name,
            "street_num": listing.house_num,
            "city": listing.city,
            "state": listing.state,
            "zip": listing.zip_code,
            "size": listing.house_size,
            "prop_size": listing.property_size,
            "beds": listing.num_beds,
            "baths": listing.num_baths,
            "listing_date": listing.list_date,
            "asking": listing.asking_price,
            "description": listing.description,
            "street_url": listing.street_name.replace(" ", "_"),
            "city_url": listing.city.replace(" ", "_"),
            "isCreator": isCreator,
            "isLender": isLender,
            "isAppraiser": isAppraiser
        }
        # Get the realtor data we need. Realtor ID = their User ID, so go straight there
        realtor_usr = listing.realtor
        # user should be a realtor, else something's fishy and we should throw and exception
        assert realtor_usr.user_type == USER_TYPE_TO_CODE["realtor"]
        if "email" in request.session:
            user = User.objects.get(email=request.session["email"])
            context["user_type"] = user.user_type
        else:
            context["user_type"] = -1
        context.update(
            {
                "realtor_fname": realtor_usr.f_name,
                "realtor_lname": realtor_usr.l_name,
                "realtor_email": realtor_usr.email,
            }
        )
        # TOOD: Once we have listing images, look for them and add their paths to a list in context
        context["listing_images"] = []
    except Exception as e:
        print(f"Exception in listing view: {e}")
        raise e
    return render(request, context=context, template_name="Williz/listing.html")

#

def admin_listing_update(request, **kwargs):
    """
    Function to update a real estate listing with the data sent by an admin's HTTP POST request. If the listing
    is deleted, redirects them to the home page. Else redirects them to the original listing.
    :param request: HTTP GET request
    :param kwargs: Keyword arguments to find the unique listing
    :return: HTTP Redirect
    """
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in kwargs
    # If user session not set redirect them to home page to log in
    if "email" not in request.session:
        return HttpResponseRedirect(f"/?&status=not_logged_in")
    email = request.session.get("email")
    user = User.objects.get(email=email)
    # Boot user to home page if they are not an admin
    if user.user_type != USER_TYPE_TO_CODE["admin"]:
        print(f"Invalid user type {CODE_TO_USER_TYPE[user.user_type]} tried to access admin listing page edit.")
        return HttpResponseRedirect("/?&status=non_admin_user")
    try:
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        if len(listing_set) != 1:
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        context = {
            "street": listing.street_name,
            "house_num": listing.house_num,
            "city": listing.city,
            "state": listing.state,
            "zip": listing.zip_code,
            "size": listing.house_size,
            "prop_size": listing.property_size,
            "beds": listing.num_beds,
            "baths": listing.num_baths,
            "listed_date": listing.list_date,
            "asking": listing.asking_price,
            "description": listing.description,
            "street_url": listing.street_name.replace(" ", "_"),
            "city_url": listing.city.replace(" ", "_"),
        }
        print(request.session["email"])
    except Exception as e:
        print(f"Exception in listing view: {e}")
        raise e
    return render(request, context=context, template_name="Williz/AdminUpdateListing.html")


def delete_listing_confirmation(request, **kwargs):
    """
    Author: Mike
    View function to confirm the deletion of a listing. If the post is submitted with the yes-button pressed then the
    listing will be deleted.
    :param request: HTTP GET request
    :param kwargs: Keyword url arguments to get the unique listing to delete
    :return: HTTP Response
    """
    # Check session, if invalid, or no user type redirect home
    valid_session, u_type = check_session(request)
    if not valid_session or u_type == -1:
        return HttpResponseRedirect("/?&status=invalid_session")
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in kwargs
        # If user session not set redirect them to home page to log in
    if "email" not in request.session:
        return HttpResponseRedirect(f"/?&status=not_logged_in")
    email = request.session.get("email")
    user = User.objects.get(email=email)
    # Boot user to home page if they are not an admin or realtor
    if user.user_type not in (USER_TYPE_TO_CODE["admin"], USER_TYPE_TO_CODE["realtor"]):
        print(f"Invalid user type {CODE_TO_USER_TYPE[user.user_type]} tried to delete a listing.")
        return HttpResponseRedirect("/?&status=non_authorized_user")
    try:
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        if len(listing_set) != 1:
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        # If they are a realtor, still need to check that they are the right realtor
        if user.user_type != USER_TYPE_TO_CODE["admin"] and user.pk != listing.realtor.user_id:
            print(
                f"Unauthorized attempt to delete a listing by realtor: {user.pk} which was created by {listing.realtor}")
            return HttpResponseRedirect("/?&status=non_authorized_user")
        context = {
            "street": listing.street_name,
            "street_num": listing.house_num,
            "city": listing.city,
            "state": listing.state,
            "zip": listing.zip_code,
            "street_url": listing.street_name.replace(" ", "_"),
            "city_url": listing.city.replace(" ", "_")
        }
        return render(request, context=context, template_name="Williz/confirmListingDelete.html")
    except Exception as e:
        print(f"Exception raised while confirming deletion of property. {e}")
        raise e


def delete_listing_handler(request, **kwargs):
    print(f"HTTP Method: {request.method}")
    if request.method != "POST":
        return HttpResponseRedirect("/?&status=invalid_http_method")
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in request.POST
    try:
        listing_set = Listing.objects.filter(house_num=int(request.POST["house_num"])) \
            .filter(street_name=request.POST["street"].replace("_", " ").strip()) \
            .filter(city=request.POST["city"].replace("_", " ").strip()) \
            .filter(state=request.POST["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(request.POST["zip"]))
        if len(listing_set) != 1:
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        street = listing.street_name
        street_num = listing.house_num
        listing.delete()
        return HttpResponseRedirect(f"/?&status={street_num}_{street}_listing_deleted")
    except Exception as e:
        print(f"Exception while trying to delete listing. {e}")
        raise e
    return HttpResponseRedirect("/?&status=failed_listing_deletion")


def test_upload(request):
    return render(request, template_name="Williz/appraisal_upload.html")


def pdf_upload_handler(request):
    """
    Author: Mike
    Handler view used to upload PDF files to the server. These PDFs are the appraisal documents
    uploaded by appraisers.
    :param request: http POST
    :return: http response
    """
    if request.method != "POST":
        print("method", request.method)
        return HttpResponseRedirect("../?&status=invalid_upload_method")
    print("Form files content: ", request.FILES.keys())
    if "pdf" not in request.FILES:
        return HttpResponseRedirect("../?&status=missing_pdf")
    try:
        pdf = request.FILES["pdf"]
        print("upload file methods", dir(pdf))
        app_type = "1004" if request.POST["form_type"] == "1004" else "1073"
        app_id = 1 #TODO: Make this appraisal id
        file_writer(pdf.read(), f"Appraisals/{app_id}/", f"Appraisal{app_id}_{app_type}.pdf")
    except Exception as e:
       print(e)
       return HttpResponseRedirect("../?&status=internal_error")

    return HttpResponseRedirect("/searchListings")



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


def updateListing(request, **kwargs):
    """
        Author: Zak
        Function which allows realtor to make changes to listing as needed
        :return: redirect to listing page with updated info
    """
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in kwargs
    try:
        print("req= ", request.POST)
        listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
            .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
            .filter(city=kwargs["city"].replace("_", " ").strip()) \
            .filter(state=kwargs["state"].replace("_", " ").strip()) \
            .filter(zip_code=int(kwargs["zip"]))
        if len(listing_set) != 1:
            raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
        listing = listing_set[0]
        if request.session["email"] == User.objects.get(user_id=listing.realtor.user_id).email:
            co_name = "No Lender Assigned"
            lender = listing.lender
            if lender is not None:
                co_name = lender.co_name
            context = {
                "street": listing.street_name,
                "house_num": listing.house_num,
                "city": listing.city,
                "state": listing.state,
                "zip": listing.zip_code,
                "size": listing.house_size,
                "prop_size": listing.property_size,
                "beds": listing.num_beds,
                "baths": listing.num_baths,
                "listed_date": listing.list_date,
                "asking": listing.asking_price,
                "description": listing.description,
                "street_url": listing.street_name.replace(" ", "_"),
                "city_url": listing.city.replace(" ", "_"),
                "lender": co_name,
                "states": [{"stat":k, "abbr":v} for k,v in STATE_NAMES.items()]
            }
            print(request.session["email"])
        else:
            return HttpResponseRedirect("/?&status=non_authorized_user")
    except Exception as e:
        print(f"Exception in listing view: {e}")
        raise e
    return render(request, context=context, template_name="Williz/UpdateListing.html")


def update(request, **kwargs):
    """
        Author: Zak
        Processes new data for listing into database
    """
    for arg_name in ("state", "house_num", "zip", "city", "street"):
        assert arg_name in kwargs
    listing_set = Listing.objects.filter(house_num=int(kwargs["house_num"])) \
        .filter(street_name=kwargs["street"].replace("_", " ").strip()) \
        .filter(city=kwargs["city"].replace("_", " ").strip()) \
        .filter(state=kwargs["state"].replace("_", " ").strip()) \
        .filter(zip_code=int(kwargs["zip"]))
    if len(listing_set) != 1:
        raise ValueError(f"Found {len(listing_set)} listings, expected to find one.")
    listing = listing_set[0]
    lender = MortgageCo.objects.get(co_name=request.POST["lender"])
    listing.house_num = request.POST["house_num"]
    listing.street_name = request.POST["street"]
    listing.city = request.POST["city"]
    listing.state = request.POST["state"]
    listing.zip_code = request.POST["zip"]
    listing.house_size = request.POST["house_size"]
    listing.property_size = request.POST["prop_size"]
    listing.num_beds = request.POST["bed_num"]
    listing.num_baths = request.POST["bath_num"]
    listing.asking_price = request.POST["ask_price"]
    listing.description = request.POST["desc"]
    listing.lender = lender
    listing.save()
    realtor_usr = listing.realtor
    context = {
        "street": listing.street_name,
        "house_num": listing.house_num,
        "city": listing.city,
        "state": listing.state,
        "zip": listing.zip_code,
        "size": listing.house_size,
        "prop_size": listing.property_size,
        "beds": listing.num_beds,
        "baths": listing.num_baths,
        "listed_date": listing.list_date,
        "asking": listing.asking_price,
        "description": listing.description,
        "street_url": listing.street_name.replace(" ", "_"),
        "city_url": listing.city.replace(" ", "_"),
        "realtor_fname": realtor_usr.f_name,
        "realtor_lname": realtor_usr.l_name,
        "realtor_email": realtor_usr.email,
        "lender": lender.co_name
    }
    return HttpResponseRedirect(
        f"/listing/{context['state']}/{context['zip']}/{context['city_url']}/{context['street_url']}/{context['house_num']}")


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
def load_key():
    key = Fernet.generate_key()
    return key


def encrypt(binfile, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(binfile)
    return encrypted_data


def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data


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
        for thing in (hmac_received, nonce_received, email, dev_id):
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
            return verify_hmac_hex_digest(skey=SECRET_KEY, email=email, nonce=nonce, hmac_hex_received=hmac_received)
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
        # return True
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
        if len(FailedLoginAttempt.objects.filter(user=user_pk).filter(
                when__gte=time_window)) >= FAILED_LOGINS_THRESHOLD:
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


def check_session(request):
    """
    Author: Mike
    Check is a session cookie is valid. Returns a pair (bool, int). The first value represents whether
    the session was valid or not. The second return value is the user-type enum, with -1 representing N/A.
    If the session is valid, the request session is mutated in-place so that the session cookie is refreshed
    and the session duration extended.
    :param request: Django http request
    :return: dictionary
    """
    is_valid, u_type = False, -1  # Default to invalid session, user is N/A
    print(f"Expiry age: {request.session.get_expiry_age()}")
    print(f"Expiration datetime: {request.session.get('expires')}")
    print(f"Email: {request.session.get('email')}")
    # If no session, or session is missing an email it's invalid
    if "sessionid" not in request.COOKIES or not request.session.get("email", default=False):
        print("Session not set, or missing an email")
        return is_valid, u_type
    # Likewise if the session has expired it's invalid
    now = timezone.now()
    if now >= request.session.get("expires", default=now):
        print("Session has expired, or was missing an expiration datetime")
        return is_valid, u_type
    try:
        email = request.session.get("email")
        u_type = User.objects.get(email=email).user_type
        is_valid = True
        # Update the session as the user was active
        request.session["expires"] = timezone.now() + timedelta(seconds=SESSION_EXPIRATION)
    except User.DoesNotExist as e:
        print(f"Session has an email which DNE in User table.")
    return is_valid, u_type
  
  
def file_writer(binary_file, filepath, filename, key=None):
    """
    Author: Mike
    :param binary_file:
    :param filepath:
    :param filename:
    :return: None sucka
    """
    full_path = join(ROOT_FILES_DIR, filepath)
    if not isdir(full_path):
        os.makedirs(full_path)
    if key is None:
        with open(join(full_path, filename), "wb") as f:
            f.write(binary_file)
    else:

        encrypt(binary_file, )
# Zak's helper functions
# ...*tumble weed blows in wind*
