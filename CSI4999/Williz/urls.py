from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("profile/", views.profile, name="profile"),
    path("verify/email/<verify_string>", views.email_verification_page, name="verify email"),
    # TODO: Delete this path once account creation is a thing. This path is just for testing email verif
    path("force/make/email/verification/<email>", views.force_make_email_verification, name="DELETE ME")
]