from django.shortcuts import render
from django.http import request, response, HttpResponse

# Create your views here.

def index(request):
    return HttpResponse("<h1>Hello Williz!</h1>")
