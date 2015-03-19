from flask_wtf import Form
from wtforms import TextField, validators, TextAreaField, \
    SubmitField, widgets, SelectMultipleField, PasswordField
# SAMPLE DATA, CHANGE FOR TAGS
data = [('value_a', 'Value A'), ('value_b', 'Value B'), ('value_c', 'Value C')]


class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class UpdateForm(Form):
    head = TextField('Title', validators=[validators.Required()])
    body = TextAreaField('Body', validators=[validators.Required()])
    tags = MultiCheckboxField('Pick some tags',
                              choices=data,
                              validators=[validators.Required()])

    submit = SubmitField('Post', )


class LoginForm(Form):
    username = TextField('username', validators=[validators.required()])
    passwd = PasswordField('password', validators=[validators.required()])
