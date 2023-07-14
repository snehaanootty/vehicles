from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from rest_framework.viewsets import ViewSet, ModelViewSet, GenericViewSet
from myapp.models import Vehicle, User
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import mixins
from rest_framework import authentication

from .permissions import SuperadminPermission, AdminPermission, UserPermission
from .serializers import VehicleSerializer, UserSerializer


# Create your views here.

class UserCreationView(ModelViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    http_method_names = ['post']


class VehicleCreateView(GenericViewSet, mixins.CreateModelMixin):
    serializer_class = VehicleSerializer
    queryset = Vehicle.objects.all()
    authentication_classes = [authentication.BasicAuthentication]
    permission_classes = [SuperadminPermission]


class VehicleListView(GenericViewSet, mixins.ListModelMixin):
    serializer_class = VehicleSerializer
    queryset = Vehicle.objects.all()
    authentication_classes =[JWTAuthentication]
    permission_classes = [UserPermission]


class VehicleUpdateView(GenericViewSet, mixins.UpdateModelMixin):
    serializer_class = VehicleSerializer
    queryset = Vehicle.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [ AdminPermission]


class VehicleRetrieveView(GenericViewSet, mixins.RetrieveModelMixin):
    serializer_class = VehicleSerializer
    queryset = Vehicle.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [ UserPermission]


class VehicleDestroyView(GenericViewSet, mixins.DestroyModelMixin):
    serializer_class = VehicleSerializer
    queryset = Vehicle.objects.all()
    authentication_classes = [JWTAuthentication]
    permission_classes = [SuperadminPermission]

