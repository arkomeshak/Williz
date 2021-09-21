from django.shortcuts import render
from django.http import request, response, HttpResponse

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
