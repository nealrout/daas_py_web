from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("", views.dashboard_view, name="dashboard"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("fetch-tab-data/<str:tab_name>/", views.fetch_tab_data, name="fetch_tab_data"),
    path("dashboard_og/", views.dashboard_og_view, name="dashboard_og"),
    path("logout/", views.logout_view, name="logout"),
    path("index/", views.index, name="index"),
    path("userfacility_assignment/", views.userfacility_assignment, name="userfacility_assignment"),
    path("get_user/", views.get_user, name="get_user"),
    path("get_facility/", views.get_facility, name="get_facility"),
    path("get_user_facility/<str:username>/", views.get_user_facility, name="get_user_facility"),
    path("update_user_facility/", views.update_user_facility, name="update_user_facility"),
]
