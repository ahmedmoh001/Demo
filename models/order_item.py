from . import db
from sqlalchemy import Sequence

class OrderItem(db.Model):
    __bind_key__ = 'db'
    id = db.Column(db.Integer, Sequence('OrderItem_sequence'), unique=True, nullable=False, primary_key=True)
    order_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)