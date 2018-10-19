from flask import (render_template, url_for, flash, redirect, request, abort, Blueprint)
from flask_login import current_user, login_required


posts = Blueprint('posts', __name__)
