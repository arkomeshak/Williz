from django.db import models
from django.utils.datetime_safe import datetime
import decimal
from datetime import datetime, timedelta

# Create your models here.


class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    f_name = models.CharField(max_length=45, null=False, blank=False, default="")
    l_name = models.CharField(max_length=45, null=False, blank=False, default="")
    pw_salt = models.CharField(max_length=10, null=True, default="salt")
    pw_hash = models.CharField(max_length=300, null=True, default="default")
    email = models.CharField(max_length=50, null=False, blank=False, default="", unique=True)
    user_type = models.IntegerField(null=False)
    register_date = models.DateTimeField(null=False, default=datetime.now)
    verification_status = models.BooleanField(null=False, default=False)
    email_validation = models.BooleanField(null=False, default=False)


class MortgageCo(models.Model):
    co_id = models.AutoField(primary_key=True)
    co_name = models.CharField(max_length=50, null=False, default="", unique=True)


class Appraiser(models.Model):
    user_id = models.ForeignKey(User, primary_key=True, on_delete=models.CASCADE)
    lic_state = models.CharField(max_length=2, null=False, default="")
    lic_num = models.CharField(max_length=10, null=False, default="")
    lic_exp_date = models.DateField(null=True, default=None)


class Lender(models.Model):
    user_id = models.ForeignKey(User, primary_key=True, on_delete=models.CASCADE)
    mortgage_co = models.ForeignKey(MortgageCo, on_delete=models.CASCADE)


class Realtor(models.Model):
    user_id = models.ForeignKey(User, primary_key=True, on_delete=models.CASCADE)
    lic_state = models.CharField(max_length=2, null=False, default="")
    lic_num = models.CharField(max_length=10, null=False, default="")
    lic_exp_date = models.DateField(null=True, default=None)


class RequestReset(models.Model):
    reset_id = models.fields.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    verification_str = models.fields.CharField(max_length=45, null=False, unique=True)
    expires = models.fields.DateTimeField(editable=False, null=False, default=(datetime.now() + timedelta(minutes=10)))


class Validation(models.Model):
    validation_id = models.fields.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    verification_str = models.fields.CharField(max_length=45, null=False, unique=True)
    expires = models.fields.DateTimeField(editable=False, null=False, default=(datetime.now() + timedelta(minutes=10)))


class DeviceCookie(models.Model):
    dev_cookie_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    nonce = models.BinaryField()
    signature = models.BinaryField()


class UntrustedLockout(models.Model):
    user_id = models.ForeignKey(User, primary_key=True, on_delete=models.CASCADE)
    lock_exp = models.fields.DateTimeField(default=None)


class FailedLoginAttempt(models.Model):
    attempt_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    when = models.fields.DateTimeField(default=datetime.now())
    device_cookie = models.ForeignKey(DeviceCookie, on_delete=models.CASCADE, null=True)


class DeviceLockout(models.Model):
    dev_lockout_id = models.AutoField(primary_key=True)
    lock_exp = models.fields.DateTimeField(default=None)
    device_cookie = models.ForeignKey(DeviceCookie, on_delete=models.CASCADE)


class Listing(models.Model):
    listing_id = models.AutoField(primary_key=True)
    house_num = models.IntegerField(null=False)
    street_name = models.CharField(max_length=25, null=False)
    city = models.CharField(max_length=30, null=False)
    state = models.CharField(max_length=2, null=False, default="")
    zip_code = models.SmallIntegerField(null=False)
    house_size = models.IntegerField(null=False)
    property_size = models.IntegerField(null=False)
    num_beds = models.SmallIntegerField(null=False)
    num_baths = models.DecimalField(max_digits=3, null=False, decimal_places=1)
    list_date = models.DateField(null=False, default=datetime.now)
    asking_price = models.IntegerField(null=False)
    realtor = models.ForeignKey(User, on_delete=models.CASCADE)
    lender = models.ForeignKey(MortgageCo, on_delete=models.CASCADE, null=True)
    appraiser = models.ForeignKey(Appraiser, on_delete=models.CASCADE, null=True)
    description = models.CharField(max_length=1000, null=True)
    image_count = models.IntegerField(null=False, default=0)


class Appraisal(models.Model):
    appraisal_id = models.AutoField(primary_key=True)
    listing = models.ForeignKey(Listing, null=True, on_delete=models.CASCADE)
    appraiser = models.ForeignKey(Appraiser, on_delete=models.CASCADE)
    mortgage_co = models.ForeignKey(MortgageCo, null=True, on_delete=models.CASCADE)
    image_count = models.IntegerField(null=False, default=0)
    enc_key = models.CharField(null=False, max_length=44, default="")
    is_complete = models.BooleanField(null=False, default=False)
