from django.urls import path, include
from .views import  SignUpView, main_page, LoginView, UserEditView, ProfileView
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', main_page, name="main"),
    path('auth/registration/', SignUpView.as_view(), name="registration"),
    path('auth/login', LoginView.as_view(), name="login"),
    path('auth/logout', LogoutView.as_view(next_page="main"), name="logout"),
    path('edit/<int:pk>', UserEditView.as_view(), name="user_edit"),
    path('profile/<int:pk>', ProfileView.as_view(),name="profile")
]
