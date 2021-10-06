from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("adminLogin/", views.adminLogin, name="adminLogin"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("profile/email/<email>", views.profile, name="profile"),
    path("resetPassword/", views.resetPassword, name="resetPassword"),
    path("resetPassword_Handler/", views.resetPassword_Handler, name="resetPassword_Handler"),
    path("resetPasswordVerify/", views.resetPasswordVerify, name="resetPasswordVerify"),
    path("verify/email/<verify_string>", views.email_verification_page, name="verify email"),
    path("profile/edit_user_info", views.edit_user_info, name="update"),
    path("register_user_handler/", views.register_user_handler, name="register_user_handler"),
    path("login_handler/", views.login_handler, name="login_handler"),
    path("createListing/email/<email>", views.create_listing, name="createListing"),
    path("create_listing_handler/", views.create_listing_handler, name="create_listing_handler")
    path("adminLogin_handler/", views.adminLogin_handler, name="adminLogin_handler"),
    path("accountRequests/", views.accountRequests, name="accountRequests"),
    path("delete_user_account/<user_id>", views.delete_user_account, name="delete_user_account"),
    path("change_verification/email/<email>", views.change_verification, name="changeVerification")
]