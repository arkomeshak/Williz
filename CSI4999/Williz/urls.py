from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),

    path("profile/email/<email>", views.profile, name="profile"),
    path("resetPassword/", views.resetPassword, name="resetPassword"),
    path("resetPassword_Handler/", views.resetPassword_Handler, name="resetPassword_Handler"),
    path("resetPasswordVerify/", views.resetPasswordVerify, name="resetPasswordVerify"),
    path("verify/email/<verify_string>", views.email_verification_page, name="verify email"),
    # TODO: Delete this path once account creation is a thing. This path is just for testing email verif
    path("force/make/email/verification/<email>", views.force_make_email_verification, name="DELETE ME"),
    path("profile/edit_user_info", views.edit_user_info, name="update"),
    path("register_user_handler/", views.register_user_handler, name="register_user_handler"),
    path("login_handler/", views.login_handler, name="login_handler")
]