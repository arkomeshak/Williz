from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(User)
admin.site.register(Appraiser)
admin.site.register(Lender)
admin.site.register(Realtor)
admin.site.register(RequestReset)
admin.site.register(Validation)
admin.site.register(MortgageCo)
admin.site.register(Listing)
admin.site.register(DeviceCookie)
admin.site.register(UntrustedLockout)
admin.site.register(FailedLoginAttempt)
admin.site.register(DeviceLockout)
admin.site.register(Appraisal)
