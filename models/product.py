from . import db
from sqlalchemy import Sequence
from datetime import datetime

class Product(db.Model):
    __bind_key__ = 'db'
    id = db.Column(db.Integer, Sequence('Product_sequence'), unique=True, nullable=False, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(100))
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    book_type_id = db.Column(db.Integer)
    stock = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255))
    created_by = db.Column(db.Integer)
    created_at = db.Column(db.TIMESTAMP, default=datetime.now)