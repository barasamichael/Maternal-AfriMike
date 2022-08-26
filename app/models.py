import flask
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as serializer
from datetime import datetime

from . import db, login_manager

#register load_user to be called when info about logged in user is required
@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))


class Permission:
    VISIT = 1
    MEMBER = 2
    GROUP_MEMBER = 4
    VIEW = 8
    REGISTER = 16
    MODERATE = 32
    ADMIN = 64


class role(db.Model):
    __tablename__ = 'role'

    role_id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), nullable = False, unique = True)
    default = db.Column(db.Boolean, default = False, index = True)
    permissions = db.Column(db.Integer)

    #relationships
    users = db.relationship('user', backref = 'role', lazy = 'dynamic')

    def __init__(self, **kwargs):
        super(role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
                'Guest' : [Permission.VISIT],
                'Member' : [Permission.VISIT, Permission.MEMBER],
                'Group Member' : [Permission.VISIT, Permission.GROUP_MEMBER, 
                    Permission.MEMBER],
                'Security Personnel' :[Permission.VISIT, Permission.VIEW],
                'Junior Staff' : [Permission.VISIT, Permission.VIEW, Permission.MEMBER, 
                    Permission.REGISTER],
                'Senior Staff' : [Permission.VISIT, Permission.VIEW, Permission.REGISTER,
                    Permission.MODERATE, Permission.MEMBER],
                'Administrator' : [Permission.VISIT, Permission.VIEW, Permission.REGISTER, 
                    Permission.MODERATE, Permission.ADMIN, Permission.MEMBER]
        }
        
        default_role = 'Guest'

        for r in roles:
            Role = role.query.filter_by(name = r).first()
            if Role is None:
                Role = role(name = r)

            Role.reset_permission()
            for perm in roles[r]:
                Role.add_permission(perm)

            Role.default = (Role.name == default_role)
            db.session.add(Role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permission(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

            
class anonymous_user(AnonymousUserMixin):
    def can(self, permission):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = anonymous_user

class user(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key = True)

    first_name = db.Column(db.String(128), nullable = False)
    middle_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    date_of_birth = db.Column(db.Date, default = datetime.utcnow, nullable = False)

    gender = db.Column(db.String(8), default = 'female', nullable = False)
    email_address = db.Column(db.String(128), nullable = False, unique = True)
    location_address = db.Column(db.String(255), nullable = False)
    nationality = db.Column(db.String(128), default = "Kenya", nullable = False)
    id_no = db.Column(db.Integer, nullable = False, unique = True)
    associated_image= db.Column(db.String(255))

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)

    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default = False)
    active = db.Column(db.Boolean, default = True)

    #relationships
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'))

    def __init__(self,**kwargs):
        super(user, self). __init__(**kwargs)
        if self.role_id is None:
            if self.email_address == flask.current_app.config['FLASKY_ADMIN_EMAIL']:
                Role = role.query.filter_by(name = 'Administrator').first()
                self.role_id = Role.role_id

            if self.role_id is None:
                Role = role.query.filter_by(default = True).first()
                self.role_id = Role.role_id

    def can(self, perm):
        Role = role.query.filter_by(role_id = self.role_id).first()

        return self.role_id is not None and Role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration = 3600):
        s = serializer(flask.current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm' : self.id}).decode('utf-8')

    def confirm(self, token):
        s = serializer(flask.current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False

        if data.get('confirm') != self.id:
            return False

        self.confirmed = True
        db.session.add(self)

        return True


class health_practitioner(db.Model):
    __tablename__ = 'health_practitioner'

    health_practitioner_id = db.Column(db.Integer, primary_key = True)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    def __repr__(self):
        return f'<{self.health_practitioner_id}>'


class health_practitioner_type(db.Model):
    __tablename__ = 'health_practitioner_type'

    hp_type_id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(255), nullable = False, unique = True)
    description = db.Column(db.Text, nullable = False)
 
    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)

    def __repr__(self):
        return f'self.health_practitioner_id'


class health_center_type(db.Model):
    hc_type_id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(255), nullable = False)
    description = db.Column(db.Text)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def __repr__():
        return f'<{self.hc_type_id}>'


class health_center(db.Model):
    __tablename__ = 'health_center'

    health_center_id = db.Column(db.Integer, primary_key = True)
    description = db.Column(db.String(255), unique = True, nullable = False)
    email_address = db.Column(db.String(128), unique = True, nullable = False)
    phone_no = db.Column(db.String(16), nullable = False, unique = True)
    emergency_line = db.Column(db.String(), nullable = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def repr(self):
        return f'<{self.health_center_id}, {self.description}>'


class hc_contact(db.Model):
    __tablename__ = 'hc_contact'
    hc_contact_id = db.Column(db.Integer, primary_key = True)
    
    description = db.Column(db.String(), nullable = False)
    emergency = db.Column(db.Boolean, default = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def repr(self):
        return f'<{self.hc_contact_id}, {self.description}>'


class mother(db.Model):
    __tablename__ = 'mother'
    mother_id = db.Column(db.Integer, primary_key = True)

    first_name = db.Column(db.String(128), nullable = False)
    middle_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    date_of_birth = db.Column(db.Date, default = datetime.utcnow, nullable = False)

    gender = db.Column(db.String(8), default = 'female', nullable = False)
    email_address = db.Column(db.String(128), nullable = False, unique = True)
    location_address = db.Column(db.String(255), nullable = False)
    nationality = db.Column(db.String(128), default = "Kenya", nullable = False)
    national_id_no = db.Column(db.Integer, nullable = False, unique = True)
    associated_image = db.Column(db.String(255))

    #relationships
    pregnancies = db.relationship('pregnancy', backref = 'mother', lazy = 'dynamic')


    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def repr(self):
        return f'<{self.mother_id}, {self.national_id_no}>'


class child(db.Model):
    __tablename__ = 'child'
    child_id = db.Column(db.Integer, primary_key = True)  

    first_name = db.Column(db.String(128), nullable = False)
    middle_name = db.Column(db.String(128))
    last_name = db.Column(db.String(128))
    date_of_birth = db.Column(db.Date, default = datetime.utcnow, nullable = False)
    
    #relationships
    pregnancy_id = db.Column(db.Integer, db.ForeignKey('pregnancy.pregnancy_id'), 
            nullable = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def __repr__(self):
        return f'<{self.child_id}, {self.first_name} {self.last_name}>'


class document(db.Model):
    __tablename__ = 'document'

    document_id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(255), unique = True, nullable = False)

    #relationships
    mother_id = db.Column(db.Integer, db.ForeignKey('mother.mother_id.'), nullable = False)
    type_id = db.Column(db.Integer, db.ForeignKey('document_type.document_type_id'), 
            nullable = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def repr(self):
        return f'<{self.document_id}, {self.filename}>'


class document_type(db.Model):
    __tablename__ = 'document_type'
    document_type_id = db.Column(db.Integer, primary_key = True)
    description = db.Column(db.String(255), nullable = False)

    #relationships
    documents = db.relationship('document_type', backref = 'document_type', lazy = 'dynamic')
    
    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    def repr(self):
        return f'<{self.document_type_id}, {self.description}>'


class pregnancy(db.Model):
    __tablename__ = 'pregnancy'

    pregnancy_id = db.Column(db.Integer, primary_key = True)
    gestation = db.Column(db.Integer, nullable = False)

    #relationships
    mother_id = db.Column(db.Integer, db.ForeignKey('mother.mother_id'), nullable = False)
    
    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    def repr(self):
        return f'<{self.pregnancy_id}, {self.gestation}>'


class complication(db.Model):
    __tablename__ = 'complication'
    complication_id = db.Column(db.Integer, primary_key = True)

    description = db.Column(db.Text, nullable = False)
    period = db.Column(db.String(128), nullable = False)

    def __repr__():
        return f'<>'


class parturition():
    __tablename__ = 'parturition'
    parturition_id = db.Column(db.Integer, primary_key = True)
    
    birth_weight = db.Column(db.Float, nullable = False)
    gestation = db.Column(db.Integer, nullable = False)
    mode_of_delivery = db.Column(db.String(255), nullable = False)
    assisted_reproduction = db.Column(db.String(255), nullable = False)

    def __repr__(self):
        return ''


class miscarriage():
    __tablename__ = 'miscarriage'
    miscarriage_id = db.Column(db.Integer, primary_key = True)

    trimester = db.Column(db.Integer, nullable = False)
    gestation = db.Column(db.Integer, nullable = False)
    cause = db.Column(db.String(255), nullable = False)

    mother_id = db.Column(db.Integer, db.ForeignKey('mother.mother_id'), 
            nullable = False)

    def __repr__(self):
        return '<>'


class personal_support_network(db.Model):
    __tablename__ = 'personal_support_network'
    psn_id = db.Column(db.Integer, primary_key = True)

    description = db.Column(db.Integer, nullable = False)
    context = db.Column(db.String(255), default = 'comprehensive', 
            nullable = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def __repr__():
        return f''


class social_history(db.Model):
    __tablename__ = 'social_history'

    social_history_id = db.Column(db.Integer, primary_key = True)
    accomodation_type = db.Column(db.String(255), nullable = False)
    smoking = db.Column(db.String(128), nullable = False)
    alcohol = db.Column(db.String(128), nullable = False)
    recreational_drug = db.Column(db.String(128), nullable = False)
    occupation = db.Column(db.String(255), nullable = False)
    
    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)

    def __repr__(self):
        return f'<self.social_history_id>'


class medication_history():
    __tablename__ = 'medication_history'

    medication_history_id = db.Column(db.Integer, primary_key = True)

    description = db.Column(db.String(255), nullable = False))
    remedy = db.Column(db.String(255), nullable = False)
    dosage = db.Column(db.String(), nullable = False)
    frequency = db.Column(db.String(128), nullable = False)
    start_date = db.Column(db.String(64), nullable = False)
    administration = db.Column(db.String(255), nullable = False)
    nature = db.Column(db.String(255), default = 'prescribed', 
            nullable = False)
    
    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)
    
    def __repr__(self):
        return f'<{self.medication_history_id}>'


class family_history(db.Model):
    __tablename__ = 'family_history'
    family_history_id = db.Column(db.Integer, primary_key = True)

    description = db.Column(db.String(255), nullable = False)
    status = db.Column(db.String(), nullable = False)

    date_created = db.Column(db.DateTime, default = datetime.utcnow)
    last_updated = db.Column(db.DateTime, default = datetime.utcnow,
            onupdate = datetime.utcnow)


    def repr(self):
        return f'<{self.hc_contact_id}, {self.description}>'
