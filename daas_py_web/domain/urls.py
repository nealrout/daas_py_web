from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("logout/", views.logout_view, name="logout"),
    path("", views.index, name="index"),
    path("index/", views.index, name="index"),
    path("get_users/", views.get_users, name="get_users"),
    path("get_facilities/", views.get_facilities, name="get_facilities"),
    path("get_user_facilities/<str:username>/", views.get_user_facilities, name="get_user_facilities"),
    path("update_user_facilities/", views.update_user_facilities, name="update_user_facilities"),
]
