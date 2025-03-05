from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdminOrReadonly(BasePermission):
    message = 'You must be the owner of this object.'

    def has_permission(self, request, view):
        if request.user and request.user.is_staff:
            return True
        return request.method in SAFE_METHODS


class IsOwnerOrReadonly(BasePermission):
    message = 'You must be the owner of this object.'

    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated:
            return True
        return request.method in SAFE_METHODS

    def has_object_permission(self, request, view, obj):
        if obj.user == request.user:  # review  obj.user
            return True
        return request.method in SAFE_METHODS
