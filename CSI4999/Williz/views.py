import hashlib
import random

from django.shortcuts import render
from django.http import request, response, HttpResponse, HttpResponseRedirect
from django.db import transaction, IntegrityError
from django.contrib import messages
from .models import *

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

@transaction.atomic #Carson
def register_user_handler(request):
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
