from django.db import models
from django.utils.datetime_safe import datetime
import decimal
from datetime import datetime, timedelta

# Create your models here.


class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    f_name = models.CharField(max_length=45, null=False, blank=False, default="")
    l_name = models.CharField(max_length=45, null=False, blank=False, default="")
    pw_salt = models.CharField(max_length=10, null=True)
    pw_hash = models.CharField(max_length=300, null=True)
    email = models.CharField(max_length=50, null=False, blank=False, default="", unique=True)
    user_type = models.IntegerField()
    register_date = models.DateTimeField(null=False, default=datetime.now)
    verification_status = models.BooleanField(null=False, default=False)
    email_validation = models.BooleanField(null=False, default=False)


class MortgageCo(models.Model):
    co_id = models.AutoField(primary_key=True)
    co_name = models.CharField(max_length=50, null=False, default="")


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
