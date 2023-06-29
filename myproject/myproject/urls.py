"""
URL configuration for myproject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter
from users.views import LoginAPIView,SignUpView,LogoutAPIView,VerifyEmailView,UserViewSet
from users import views
router = DefaultRouter()
router.register(r'users', views.UserViewSet)



urlpatterns = [ 
    path('admin/', admin.site.urls),
    path('api/login/', LoginAPIView.as_view(), name='login'),
    path('api/signup/', SignUpView.as_view(), name='signup'),
    path('verify-email/<str:uidb64>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('api/logout/', LogoutAPIView.as_view(), name='signup'),
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls')),
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    path('api/', include(router.urls)),
    path('users/delete_account/', UserViewSet.as_view({'delete': 'delete_account'}), name='delete-account'),
]