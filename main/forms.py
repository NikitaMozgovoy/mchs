from django.db.models import fields
from django.db.models.base import Model
from django.forms import ModelForm, widgets
from django.forms.models import ALL_FIELDS
from .models import GDZS, CustomUser, Post, PassedApprovals, InitialTrainingPeriod
from django import forms
from django.core.exceptions import ValidationError
import unicodedata
from django.contrib.auth import (
    authenticate, get_user_model, password_validation,
)
from django.contrib.auth.hashers import (
    UNUSABLE_PASSWORD_PREFIX, identify_hasher,
)
from django.contrib.auth.forms import UserCreationForm  
from django.utils.translation import gettext, gettext_lazy as _
from django.utils.text import capfirst
from betterforms.multiform import MultiModelForm
from .models import GDZS, PassedApprovals, InitialTrainingPeriod, Post

UserModel = get_user_model()

class EmailField(forms.CharField):
    """Кастомизация поля для почты"""
    def to_python(self, value):
        return unicodedata.normalize('NFKC', super().to_python(value))

    def widget_attrs(self, widget):
        return {
            **super().widget_attrs(widget),
            'autocapitalize': 'none',
            'autocomplete': 'email',
        }

class SignUpForm(forms.ModelForm):
    """Форма регистрации"""
    password = forms.CharField( #настройка поля пароля
        label=("Пароль"),
        strip=False, #убираем видимость вводимых данных
        widget=forms.PasswordInput(attrs={'autocomplete': 'new-password'}),
    )

    class Meta:
        model = CustomUser
        fields = ("email",)
        field_classes = {'email': EmailField} #используем созданное выше поле почты, пароль в список вносить не надо

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs['autofocus'] = True #если в используемых полях есть поле имени пользователя, ставим в него курсор



    def save(self, commit=True):
        """Переопределяем метод сохранения формы, устанавливая именем пользователя по умолчанию адрес электронной почты"""
        user = super().save(commit=False)
        user.fullname = user.email
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class ReadOnlyPasswordHashWidget(forms.Widget):
    """Переопределяем встроенный виджет
    https://docs.djangoproject.com/en/1.8/_modules/django/contrib/auth/forms/"""
    template_name = 'registration/widgets/read_only_password_hash.html'
    read_only = True

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        summary = []
        if not value or value.startswith(UNUSABLE_PASSWORD_PREFIX): # если поле с паролем пустое или начинается с запрещенного символа, выводим сообщение об ошибке
            summary.append({'label': gettext("No password set.")})
        else:
            try: # пробуем захэшировать введенный пароль
                hasher = identify_hasher(value)
            except ValueError:
                summary.append({'label': gettext("Invalid password format or unknown hashing algorithm.")})
            else:
                for key, value_ in hasher.safe_summary(value).items():
                    summary.append({'label': gettext(key), 'value': value_})
        context['summary'] = summary # если встроенный в Django алгоритм отрабатывает верно, добавляем пароль в контекст
        return context

    def id_for_label(self, id_):
        return None

class ReadOnlyPasswordHashField(forms.Field):
    """Аналогично. Если честно, сам не до конца понимаю как это работает, но скорее всего сам пароль и его кодировка 
    представлены в двух разных полях, одно из которых отображает значение, а другое сохраняет"""
    widget = ReadOnlyPasswordHashWidget

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("required", False)
        kwargs.setdefault('disabled', True)
        super().__init__(*args, **kwargs)

    class Meta:
        model = CustomUser
        fields = '__all__'
        field_classes = {'email': EmailField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        password = self.fields.get('password')
        if password:
            password.help_text = password.help_text.format('../password/')
        user_permissions = self.fields.get('user_permissions')
        if user_permissions:
            user_permissions.queryset = user_permissions.queryset.select_related('content_type')

class AuthenticationForm(forms.Form):
    """
    Опять же частично переопределяем встроенный класс формы для входа
    """
    email = EmailField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(
        label=_("Пароль"),
        strip=False,
        widget=forms.PasswordInput(attrs={'autocomplete': 'current-password'}),
    )

    error_messages = {
        'invalid_login': _(
            "Пожалуйста, введите действующие %(email)s и пароль. Оба поля чувствительны к регистру."
        ),
        'inactive': _("Этот аккаунт не активен"),
    }

    def __init__(self, request=None, *args, **kwargs):
        """
        Устанавливаем длину и названия полей для входа
        """
        self.request = request
        self.user_cache = None
        super().__init__(*args, **kwargs)

        self.username_field = UserModel._meta.get_field(UserModel.USERNAME_FIELD)
        email_max_length = self.username_field.max_length or 254
        self.fields['email'].max_length = email_max_length
        self.fields['email'].widget.attrs['maxlength'] = email_max_length
        if self.fields['email'].label is None:
            self.fields['email'].label = capfirst(self.username_field.verbose_name)

    def clean(self):
        """Проверка введенных данных"""
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        if email is not None and password:
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data

    def confirm_login_allowed(self, user):
        """
        Проверяем активен ли аккаунт пользователя, который пытается войти
        """
        if not user.is_active: # если нет, вызываем исключение с сообщением из списка ошибок выше
            raise ValidationError(
                self.error_messages['inactive'],
                code='inactive',
            )

    def get_user(self):
        return self.user_cache

    def get_invalid_login_error(self):
        """Метод вызывается при ошибке ввода лоигна"""
        return ValidationError(
            self.error_messages['invalid_login'],
            code='invalid_login',
            params={'email': self.username_field.verbose_name},
        )

class UserEditForm(ModelForm):
    class Meta:
        model = CustomUser
        fields = ['id','fullname', 'post', 'rank', 'bdate', 'document']


class PassedApprovalsEditForm(ModelForm):
    class Meta:
        model = PassedApprovals
        fields = ['id','fullname','result', 'why', 'attdate', 'profdate', 'approvalsname']

class InitialTrainingPeriodEditForm(ModelForm):
    class Meta:
        model = InitialTrainingPeriod
        fields = ['id','fullname','start', 'end']

class PostEditForm(ModelForm):
    class Meta:
        model = Post
        fields = ['id','fullname','rtp', 'passdate', 'value']

class GDZSEditForm(ModelForm):
    class Meta:
        model=GDZS
        fields=['id','fullname','value','possible', 'why_not']

class UserEditMultiForm(MultiModelForm):
    """Класс из библиотеки betterforms, который позволяет на одной странице отображать и сохранять сразу несколько форм"""
    # указываем используемые формы
    form_classes = { 
        'user': UserEditForm,
        'passedapprovals': PassedApprovalsEditForm,
        'period': InitialTrainingPeriodEditForm,
        'post': PostEditForm,
        'gdzs':GDZSEditForm
    }
    def save(self, commit=True):
        """Метод проверки введенных данных, в нашем случае еще и их изменение.
        Технически Django не может сохранять больше одной модели на страницу, поэтому отображаемые формы являются абстрактными, не связанными с моделями.
        Данные из них перед сохранением мы забираем и сами заносим в модели.
        """
        objects = super(UserEditMultiForm, self).save(commit=False)

        if commit:
            # user выступает основной моделью в этой связке форм, поэтому можно ее сохранить сразу
            user = objects['user']
            user.save()
            # проверяем что есть модель связанная с текущим пользователем и именно она сейчас используется
            # возможна условная ситуация, что у одного работника две профессии, но в профиле используется только одна или не используется вообще,
            # поэтому нужно проверить связь с двух сторон
            if objects['passedapprovals'].fullname==user and user.approvals: 
                # если модель есть, то меняем ее данные в соответствии с введенными
                passedapprovals = objects['passedapprovals']
                object = PassedApprovals.objects.get(fullname=user) 
                object.result = passedapprovals.result
                if object.result == None: # если поле в форме осталось пустым, задаем ему значение для лучшего отображения и сохранения в БД
                    object.why = "Неизвестно"
                else:
                    object.why = passedapprovals.why
                if object.result==False: # если аттестация не была пройдена, то ввод связанных с ней данных не логичен. Чтобы это контролировать, удаляем их сами
                    object.attdate = None
                    object.approvalsname = None
                    object.profdate = None
                else: # иначе сохраняем введенные данные
                    object.attdate = passedapprovals.attdate
                    object.profdate = passedapprovals.profdate
                    object.approvalsname = passedapprovals.approvalsname
                object.save()
            else: 
                passedapprovals = objects['passedapprovals']
                object = PassedApprovals() # если связанная модель не найдена, то создаем новую
                object.fullname = user # и сами связываем через значение внешнего ключа с изменяемым пользователем
                object.result = passedapprovals.result # далее принцип сохранения тот же
                if object.result == None:
                    object.why = "Неизвестно"
                else:
                    object.why = passedapprovals.why
                if object.result==False:
                    object.attdate = None
                    object.approvalsname = None
                    object.profdate = None
                else:
                    object.attdate = passedapprovals.attdate
                    object.profdate = passedapprovals.profdate
                    object.approvalsname = passedapprovals.approvalsname
                object.save()
            # опять проверяем наличие и связь, но уже другой модели и сохраняем по тому же принципу с соблюдением логики
            if objects['period'].fullname==user and user.period: 
                period = objects['period']
                object = InitialTrainingPeriod.objects.get(fullname=user)
                object.start = period.start
                object.end = period.end
                object.save()
            else:
                period = objects['period']
                object =InitialTrainingPeriod()
                object.start = period.start
                object.end = period.end
                object.save()

            if objects["post"].fullname==user and user.post:
                post = objects['post']
                object = Post.objects.get(fullname=user)
                object.value = post.value
                object.rtp = post.rtp
                if object.rtp == False:
                    object.passdate = None    
                else:
                    object.passdate = post.passdate
                object.save()
            else:
                post = objects['post']
                object = Post()
                object.fullname = user
                object.value = post.value
                object.rtp = post.rtp
                if object.rtp == False:
                    object.passdate = None    
                else:
                    object.passdate = post.passdate
                object.save()
                
            if objects['gdzs'].fullname==user and user.gdzs:
                gdzs = objects['gdzs']
                object = GDZS.objects.get(fullname=user)
                object.value = gdzs.value
                if object.value == True:
                    object.possible = True
                else:
                    object.possible = gdzs.possible
                object.why_not = gdzs.why_not
                object.save()
            else:
                gdzs = objects['gdzs']
                object = GDZS()
                object.fullname = user
                object.value = gdzs.value
                if object.value == True:
                    object.possible = True
                else:
                    object.possible = gdzs.possible
                object.why_not = gdzs.why_not
                object.save()

        return objects
