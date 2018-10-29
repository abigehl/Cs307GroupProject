from files import app, db, rec
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    # rec = rec(rec_name='Ice Cubes',
    #           rec_description='Some delicious ice cubes of water',
    #           rec_instruction='Put in freezer for 30 minutes.Then take them out and enjoy',
    #           ing_1='water', user_id=3)
    # db.session.add(rec)
    # db.session.commit()
    app.run(debug=True)
    # manager.run()
