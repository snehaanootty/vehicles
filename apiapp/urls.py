from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views

router = DefaultRouter()

router.register('register', views.UserCreationView, basename='users')

urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='two_jwt'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh_token'),
    path('vehicles/',
         views.VehicleListView.as_view({'get': 'list'}), name='vehicle-list'),
    path('vehicles/create/',
         views.VehicleCreateView.as_view({'post': 'create'}), name='vehicle-create'),
    path('vehicles/<int:pk>/',
         views.VehicleRetrieveView.as_view({'get': 'retrieve'}), name='vehicle-retrieve'),
    path('vehicles/<int:pk>/update/', views.VehicleUpdateView.as_view(
        {'put': 'update'}), name='vehicle-update'),
    path('vehicles/<int:pk>/delete/',
         views.VehicleDestroyView.as_view({'delete': 'destroy'}), name='vehicle-delete'),

]+router.urls
