"""WTForms definitions for the authentication flow."""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField, HiddenField, IntegerField, PasswordField, SelectField, StringField,
    SubmitField, TextAreaField,
)
from wtforms.validators import DataRequired, Length, Regexp

from ..registry.identity import DOC_TYPES

DOC_LABELS = {
    "passport_rf": "Паспорт РФ",
    "foreign_passport": "Загранпаспорт",
    "residence_permit": "Вид на жительство",
}


class RegisterForm(FlaskForm):
    login = StringField(
        "Логин",
        validators=[
            DataRequired(message="укажите логин"),
            Length(min=3, max=32, message="3–32 символа"),
            Regexp(r"^[a-zA-Z0-9._-]+$", message="только латиница, цифры, . _ -"),
        ],
    )
    password = PasswordField(
        "Пароль",
        validators=[
            DataRequired(message="укажите пароль"),
            Length(min=12, max=128, message="12–128 символов"),
        ],
    )
    fio = StringField(
        "ФИО как в документе",
        validators=[DataRequired(message="укажите ФИО"), Length(min=5, max=120)],
    )
    dob = StringField(
        "Дата рождения (ГГГГ-ММ-ДД)",
        validators=[DataRequired(message="укажите дату рождения"), Length(min=10, max=10)],
    )
    doc_type = SelectField(
        "Документ",
        choices=[(code, DOC_LABELS[code]) for code in sorted(DOC_TYPES & set(DOC_LABELS))],
        validators=[DataRequired()],
    )
    doc_series = StringField("Серия", validators=[Length(max=10)])
    doc_number = StringField(
        "Номер", validators=[DataRequired(message="укажите номер"), Length(min=1, max=20)]
    )
    district_code = SelectField("Избирательный округ", validators=[DataRequired()], choices=[])
    consent = BooleanField(
        "Согласен на обработку персональных данных для проверки права голоса",
        validators=[DataRequired(message="нужно согласие")],
    )
    confirm = HiddenField()
    submit = SubmitField("Продолжить")


class LoginForm(FlaskForm):
    login = StringField("Логин", validators=[DataRequired(message="укажите логин"), Length(max=64)])
    password = PasswordField("Пароль", validators=[DataRequired(message="укажите пароль")])
    submit = SubmitField("Войти")


class LogoutForm(FlaskForm):
    submit = SubmitField("Выйти")


class TotpForm(FlaskForm):
    code = StringField(
        "Код из приложения",
        validators=[
            DataRequired(message="введите код"),
            Length(min=6, max=6, message="ровно 6 цифр"),
            Regexp(r"^\d{6}$", message="только цифры"),
        ],
    )
    submit = SubmitField("Подтвердить")


class RecoveryForm(FlaskForm):
    code = StringField(
        "Код восстановления",
        validators=[DataRequired(message="введите код"), Length(min=10, max=14)],
    )
    submit = SubmitField("Войти")


class VerificationForm(FlaskForm):
    """The provider is chosen by configuration, not by the applicant."""

    submit = SubmitField("Отправить заявку")


class AdminPollForm(FlaskForm):
    title = StringField("Название", validators=[DataRequired(), Length(min=5, max=200)])
    summary = StringField("Краткое описание", validators=[Length(max=600)])
    description = TextAreaField("Описание (Markdown-подмножество)")
    system = SelectField(
        "Система",
        choices=[("list", "общий список"), ("district", "по округам"), ("mixed", "смешанная")],
    )
    starts_at = StringField("Начало (UTC)", validators=[DataRequired()])
    ends_at = StringField("Окончание (UTC)", validators=[DataRequired()])
    k_threshold = IntegerField("Порог анонимности k", default=10)
    ballot_plaintext_bytes = IntegerField("Размер бюллетеня, байт", default=1024)
    key_publish_after = StringField("Публикация ключа не раньше (UTC, пусто = сразу)")
    submit = SubmitField("Сохранить")


class ContestForm(FlaskForm):
    title = StringField("Название пункта", validators=[DataRequired(), Length(max=200)])
    kind = SelectField(
        "Тип",
        choices=[("candidate", "кандидат"), ("party_list", "партийный список"), ("referendum", "вопрос")],
        default="candidate",
    )
    scope = SelectField(
        "Область", choices=[("nationwide", "вся страна"), ("district", "округ")], default="nationwide"
    )
    district_code = SelectField("Округ (для окружного пункта)", choices=[])
    allow_against_all = BooleanField("Разрешить «против всех»", default=True)
    submit = SubmitField("Добавить пункт")


class OptionForm(FlaskForm):
    name = StringField("Имя", validators=[DataRequired(), Length(max=200)])
    kind = SelectField(
        "Тип", choices=[("candidate", "кандидат"), ("party", "партия"), ("against_all", "против всех")],
        default="candidate",
    )
    bio = TextAreaField("Биография / описание")
    link_url = StringField("Ссылка (http/https)")
    display_order = IntegerField("Порядок", default=0)
    submit = SubmitField("Добавить вариант")


class DistrictForm(FlaskForm):
    district_code = SelectField("Округ", choices=[], validators=[DataRequired()])
    submit = SubmitField("Добавить округ")


class PublicKeyForm(FlaskForm):
    public_key = StringField("Публичный ключ (hex, 32 байта)", validators=[DataRequired()])
    submit = SubmitField("Зафиксировать ключ")


class PrivateKeyForm(FlaskForm):
    private_key = StringField("Приватный ключ (hex, 32 байта)", validators=[DataRequired()])
    submit = SubmitField("Опубликовать ключ")


class ActionForm(FlaskForm):
    submit = SubmitField("Выполнить")


class DeleteAccountForm(FlaskForm):
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Удалить аккаунт")


class RecoverForm(FlaskForm):
    login = StringField("Логин", validators=[DataRequired(), Length(max=64)])
    code = StringField("Код восстановления", validators=[DataRequired(), Length(min=10, max=14)])
    new_password = PasswordField(
        "Новый пароль", validators=[DataRequired(), Length(min=12, max=128)]
    )
    submit = SubmitField("Сменить пароль и войти")
