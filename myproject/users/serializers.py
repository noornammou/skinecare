from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from users.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model
import hashlib,time,json



account_activation_token = PasswordResetTokenGenerator()
User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    is_email_verified = serializers.SerializerMethodField()
    token = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'is_email_verified', 'password', 'token')
        extra_kwargs = {'password': {'write_only': True}}
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=password,
        )
        return user
    
    def get_token(self, obj):
        token, created = Token.objects.get_or_create(user=obj)
        return token.key
    
    def get_is_email_verified(self, obj):
        return obj.is_active
    
    def get_full_name(self, obj):
        return obj.get_full_name()
    
    def get_short_name(self, obj):
        return obj.get_short_name()
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'), email=email, password=password)
            if not user:
                raise serializers.ValidationError('Unable to login with provided credentials.')
            if not user.is_active:
                raise serializers.ValidationError('User account is not activated yet.')
        else:
            raise serializers.ValidationError('Must include "email" and "password".')

        data['user'] = user
        return data
    
class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255)
    user = UserSerializer()

    def create(self, validated_data):
        user_id = validated_data['user_id']
        token = validated_data['token']
        token_obj, created = Token.objects.get_or_create(user_id=user_id)
        token_obj.key = token
        token_obj.save()
        return token_obj
        
    #when a Token object is being serialized into a JSON response
    def to_representation(self, instance):
        data = super().to_representation(instance)
        user = instance.user
        data['user'] = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
        return data
    
class LogoutSerializer(serializers.Serializer):
    message = serializers.CharField(default="You have been logged out.")
    
class ActivationSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        try:
            uid = urlsafe_base64_decode(data['uidb64']).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('Invalid activation link. Please request a new activation link.')

        if account_activation_token.check_token(user, data['token']):
            if not user.is_active:
                user.is_active = True
                user.save()
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError('Invalid activation link. Please request a new activation link.')


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return {
            'user_id': user.pk,
            'timestamp': timestamp,
            'is_active': user.is_active,
        }

    def _make_hash(self, value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode('utf-8')).hexdigest()

    def _make_token_with_timestamp(self, user, timestamp):
        hash_value = self._make_hash_value(user, timestamp)
        return "{}-{}".format(timestamp, self._make_hash(hash_value))

    def make_token(self, user):
        timestamp = int(time.time())
        return self._make_token_with_timestamp(user, timestamp)


account_activation_token = AccountActivationTokenGenerator()