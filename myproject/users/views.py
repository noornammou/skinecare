from django.shortcuts import render
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from django.db import DatabaseError
from .serializers import UserSerializer, LoginSerializer,ActivationSerializer
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from users.models import User
from users.serializers import UserSerializer
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer
from django.views.decorators.csrf import csrf_exempt


User = get_user_model()


class CsrfExemptMixin(object):
    @classmethod
    def as_view(cls, **kwargs):
        view = super(CsrfExemptMixin, cls).as_view(**kwargs)
        return csrf_exempt(view)

class SignUpView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)
def post(self, request):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        password = request.data.get('password')
        try:
            user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name, password=password)
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'message': 'User created successfully.'}, status=status.HTTP_200_OK)
        except DatabaseError:
            return Response({'token': None,'message': 'Database connection failed.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({'token': None, 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
class LoginAPIView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(email=email, password=password)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'email': user.email,
                'token': token.key})
        else:
            return Response({'error': 'Invalid credentials'})
        
class LogoutAPIView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)

class ActivationViewv(generics.GenericAPIView):
    serializer_class = ActivationSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        user.is_active = True
        user.save()
        return Response({'message': 'Account activated successfully.'})
   
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    
    
