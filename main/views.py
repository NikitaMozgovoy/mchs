from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import render, redirect
from django.views.generic import CreateView, FormView, DetailView, UpdateView, DeleteView, ArchiveIndexView, TemplateView, ListView
from django.urls import reverse_lazy
from .models import CustomUser, Post, GDZS
from .forms import SignUpForm, AuthenticationForm, UserEditForm, UserEditMultiForm, PostEditForm, PassedApprovalsEditForm, GDZSEditForm
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.http import HttpResponseRedirect, QueryDict
from django.utils.http import (
    url_has_allowed_host_and_scheme, urlsafe_base64_decode,
)
from django.contrib.auth import (
    REDIRECT_FIELD_NAME, get_user_model, login as auth_login,
    logout as auth_logout, update_session_auth_hash,
)
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.shortcuts import resolve_url

@login_required
def main_page(request):
    users = CustomUser.objects.all()
    return render(request, "main/pages/main.html", {'users':users})


class SignUpView(CreateView):
    form_class = SignUpForm
    success_url = reverse_lazy('login')
    template_name = 'registration/register.html'


class SuccessURLAllowedHostsMixin:
    success_url_allowed_hosts = set()

    def get_success_url_allowed_hosts(self):
        return {self.request.get_host(), *self.success_url_allowed_hosts}


class LoginView(SuccessURLAllowedHostsMixin, FormView):
    """
    Отображает форму логина и производит процедуру входа.
    """
    authentication_form = AuthenticationForm
    next_page = 'main'
    redirect_field_name = REDIRECT_FIELD_NAME
    template_name = 'registration/login.html'
    redirect_authenticated_user = True
    extra_context = None

    @method_decorator(sensitive_post_parameters())
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs): # функция обрабатывает ошибку циклической переадресации
        if self.redirect_authenticated_user and self.request.user.is_authenticated:
            redirect_to = self.get_success_url()
            if redirect_to == self.request.path:
                raise ValueError(
                    "Redirection loop for authenticated user detected. Check that "
                    "your LOGIN_REDIRECT_URL doesn't point to a login page."
                )
            return HttpResponseRedirect(redirect_to)
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self): #функция возвращает адрес, который открывается после успешного заполнения формы
        return self.get_redirect_url() or self.get_default_redirect_url()

    def get_redirect_url(self): 
        """Возвращает установленный пользователем адрес"""
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        url_is_safe = url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ''

    def get_default_redirect_url(self):
        """Возвращает адрес установленный в переменной next_page выше или LOGIN_REDIRECT_URL в настройках"""
        return resolve_url(self.next_page or settings.LOGIN_REDIRECT_URL)

    def get_form_class(self):
        return self.authentication_form or self.form_class

    def get_form_kwargs(self):
        """Возвращает введенные в форму данные"""
        kwargs = super().get_form_kwargs()
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        """Проверка формы на валидность и переадресация"""
        auth_login(self.request, form.get_user())
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        """Обновляет словарь контекстных данных"""
        context = super().get_context_data(**kwargs)
        current_site = get_current_site(self.request)
        context.update({
            self.redirect_field_name: self.get_redirect_url(),
            'site': current_site,
            'site_name': current_site.name,
            **(self.extra_context or {})
        })
        return context


class UserEditView(UpdateView):
    """Страница изменения данных пользователя"""
    model = CustomUser
    success_url = '/'
    template_name = 'main/pages/user_edit.html'
    form_class = UserEditMultiForm


    def get_form_kwargs(self):
        """Устанавливаем значения для инициализации формы"""
        kwargs = super(UserEditView, self).get_form_kwargs()
        kwargs.update(instance={
            'user': self.object,
            'passedapprovals': self.object.approvals,
            'period': self.object.period,
            'post':self.object.post,
            'gdzs': self.object.gdzs
        })
        return kwargs

    def get_context_data(self, **kwargs):
        """Добавляем в контекст объект текущего пользователя"""
        context=super().get_context_data(**kwargs)
        context['curr'] = CustomUser.objects.get(pk=self.kwargs.get('pk'))
        return context


class ProfileView(DetailView):
    """Отображение профиля"""
    model = CustomUser
    template_name = 'main/pages/profile.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = CustomUser.objects.get(pk=self.kwargs.get('pk')) # добавляем к контексту объект запрошенного пользователя
        return context