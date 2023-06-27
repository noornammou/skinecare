from django.shortcuts import render
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer,ActivationSerializer,LogoutSerializer
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from users.models import User
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.urls import reverse
from django.http import JsonResponse
from django.views.generic import View
from django.core.mail import EmailMessage


User = get_user_model()
class SignUpView(APIView):
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        password = request.data.get('password')

    
        # Check if the user with the provided email already exists
        try:
            user = User.objects.get(email=email)

            # Check if the user's email is already validated
            if user.is_active:
                return Response({'message': 'This email already exists.'}, status=status.HTTP_409_CONFLICT)
            else:
                # Resend verification email to user
                self.send_verification_email(user)
                return Response({'message': 'Please verify your account. We have sent you a verification email.'}, status=status.HTTP_202_ACCEPTED)

        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name, password=password)

            # Send verification email to user
            self.send_verification_email(user)

            serializer = UserSerializer(user)
            token = Token.objects.create(user=user)
            return Response({'token': token.key, 'message': 'User created successfully.'}, status=status.HTTP_201_CREATED)

        except:
            return Response({'message': 'Failed to create user.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def send_verification_email(self, user):
        # Generate verification URL for the user
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        verification_url = self.request.build_absolute_uri(reverse('verify-email', args=[uid, token]))

        # Send verification email to user
        subject = 'Verify your email address'
        message = f'Please click the following link to verify your email address: {verification_url}'
        email = EmailMessage(subject, message, to=[user.email])
        email.send()


class VerifyEmailView(View):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # Mark the user's email as verified
            user.is_active = True
            user.save()
            return JsonResponse({'message': 'Email verified successfully.'})
        else:
            return JsonResponse({'message': 'Invalid verification link.'}, status=status.HTTP_404_NOT_FOUND)

class LoginAPIView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')

        # Check if user with the provided email exists
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'This user does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Check if user's email has been verified
        if not user.is_active:
            return Response({'error': 'please verify your email .'},status=status.HTTP_403_FORBIDDEN)

        # Authenticate user with provided email and password
        user = authenticate(email=email, password=password)
        if user is not None:
            login(request, user)
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'email': user.email,
                'token': token.key}, status=200)
        else:
            return Response({'error': 'Incorrect password.'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutAPIView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        request.user.auth_token.delete()
        return Response({'message': 'You have been logged out.'}, status=status.HTTP_200_OK)

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
    
    
    
