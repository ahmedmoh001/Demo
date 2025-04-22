from . import db
from sqlalchemy import Sequence
from datetime import datetime

class Order(db.Model):
    __bind_key__ = 'db'
    id = db.Column(db.Integer, Sequence('Order_sequence'), unique=True, nullable=False, primary_key=True)
    user_id = db.Column(db.Integer)
    order_date = db.Column(db.TIMESTAMP, default=datetime.now)
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)