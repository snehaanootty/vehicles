from rest_framework import serializers
from myapp.models import Vehicle, VehicleImage, User



class UserSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)
 

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "role"]

    def create(self, validated_data):
        email = validated_data.get("email")
        username = validated_data.get("username")
        password = validated_data.get("password")
        role = validated_data.get("role")
        if  email:
            user = User.objects.create(username=username, email=email, role=role) 
            user.set_password(password)
            user.save()

            return user

        user = User.objects.create(username=username, email='example@gmail.com', role=role)

        user.set_password(password)
        user.save()

        return user


class VehicleImageSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)

    class Meta:
        model = VehicleImage
        fields = ["id", "image"]


class VehicleSerializer(serializers.ModelSerializer):
    id = serializers.CharField(read_only=True)
    created_date = serializers.DateTimeField(read_only=True)
    is_active = serializers.CharField(read_only=True)
    images = VehicleImageSerializer(read_only=True, many=True)

    class Meta:
        model = Vehicle
        fields = ["id", "vehicle_number", "vehicle_type", "vehicle_model",
                  "vehicle_description", "is_active", "created_date", "images"]
