from sqlalchemy import Column, Integer, Boolean, DateTime, VARCHAR
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(VARCHAR(255), unique=True, index=True)
    full_name = Column(VARCHAR(255))
    phone = Column(VARCHAR(20), nullable=True)
    address = Column(VARCHAR(500), nullable=True)
    hashed_password = Column(VARCHAR(72))
    is_verified = Column(Boolean, default=False)
    otp_code = Column(VARCHAR(72), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)
    reset_token = Column(VARCHAR(72), nullable=True, index=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    registration_status = Column(Boolean, default=False, nullable=False)
    registered_adults = Column(Integer, default=0, nullable=False)
    registered_children_6_12 = Column(Integer, default=0, nullable=False)
    registered_children_under_6 = Column(Integer, default=0, nullable=False)
    amount_paid = Column(Integer, default=0, nullable=False)
    cashfree_transaction_id = Column(VARCHAR(255), nullable=True)
