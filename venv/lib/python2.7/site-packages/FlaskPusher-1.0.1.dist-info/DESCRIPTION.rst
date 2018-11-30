Flask-Pusher
------------

Flask-Pusher is a wrapper around `pusher-http-python` and
adds Pusher support for your Flask application.

Easy Setup
``````````

Quickstart:

.. code:: python

    from flask_pusher import Pusher

    app = Flask(__name__)
    pusher = Pusher(app)

    # Use any `pusher.Pusher` method.
    pusher.trigger('channel', 'my-event', {'data': 'It works!'})

Or using the factory pattern:

.. code:: python

    from flask_pusher import Pusher

    pusher = Pusher()

    def create_app():
        app = Flask(__name__):
        pusher.init_app(app)

        # Use any `pusher.Pusher` method.
        pusher.trigger('channel', 'my-event', {'data': 'It works!'})


Easy Installation
`````````````````

.. code:: bash

    $ pip install FlaskPusher
    $ # NOT Flask-Pusher

Links
`````

* `Source code and issues <https://github.com/Bekt/flask-pusher>`_
* `Documentation <http://flask-pusher.readthedocs.org/>`_
* `Official Pusher Python library <https://github.com/pusher/pusher-http-python>`_



