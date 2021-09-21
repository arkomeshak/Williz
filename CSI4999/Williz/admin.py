from django.contrib import admin
from .models import User, Appraiser, Lender, Realtor, RequestReset, Validation, MortgageCo

# Register your models here.
admin.site.register(User)
admin.site.register(Appraiser)
admin.site.register(Lender)
admin.site.register(Realtor)
admin.site.register(RequestReset)
admin.site.register(Validation)
admin.site.register(MortgageCo)
