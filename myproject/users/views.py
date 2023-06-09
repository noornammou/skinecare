from django.shortcuts import render
from django.conf import settings
from django.contrib.auth import authenticate, login
from django.contrib.auth.tokens import default_token_generator
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer,ActivationSerializer
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from users.models import User
from users.serializers import UserSerializer
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from .serializers import UserSerializer,LogoutSerializer
from django.views.decorators.csrf import csrf_exempt


User = get_user_model()


class SignUpView(APIView):
    permission_classes = []
    authentication_classes = [TokenAuthentication]

    @csrf_exempt
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        password = request.data.get('password')

        # Check if user with the provided email already exists
        try:
            user = User.objects.get(email=email)

            # Return error response indicating that email already exists
            return Response({'message': 'This email already exists.'}, status=400)

        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name, password=password)
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key, 'message': 'User created successfully.'}, status=201)

        except:
            return Response({'message': 'Failed to create/update user.'}, status=400)
        
        
        
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
    
    
    
