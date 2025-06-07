import traceback

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError, ProgrammingError
from passlib.hash import bcrypt
from models import User, VaultEntry
from models.base import Base

DATABASE_URL = "postgresql://postgres:cloak@172.31.144.1:5432/passman"

engine = create_engine(DATABASE_URL, echo = True)
SessionLocal = sessionmaker(bind=engine)

def create_tables():
    """Initiator, creates tables"""
    try:
        Base.metadata.create_all(engine)
        return {"message": f"User {username} added successfully"}, 200
    except SQLAlchemyError:
        print("Error creating tables:")
        traceback.print_exc()
        return {"error": "SQLAlchemyError while creating tables"}, 401

def add_user(username, password_hash, totp_secret=None):
    """Add a user to the master user table"""
    session = SessionLocal()
    return_req = {"message": ""}
    code = 200
    try:
        user_x = session.query(User).filter_by(username=username).first()
        if user_x:
            return_req, code = ({"error": "User already exists"}, 401)
        else:
            password_hash = bcrypt.hash(password_hash)
            user = User(username=username, password_hash=password_hash, totp_secret=totp_secret)
            session.add(user)
            session.commit()
            return_req, code = ({"message": f"User {username} added successfully"}, 200)
    except SQLAlchemyError:
        session.rollback()
        return_req, code = ({"error": "SQLAlchemyError while adding user"}, 401)
        traceback.print_exc()
    finally:
        session.close()
    return return_req, code

def edit_user(username, password, totp):
    """Modify user entry in the table"""
    session = SessionLocal()
    return_req = {"message": ""}
    code = 400
    try:
        user_x = session.query(User).filter_by(username=username).first()
        if user_x:
            if bcrypt.verify(password, user_x.password_hash):
                user_x.password_hash = bcrypt.hash(password)
                user_x.totp_secret = totp
                session.flush()
                session.commit()
                return_req, code = ({"message": f"User {username} modified successfully"}, 200)
            else:
                return_req, code = ({"error": f"User {username} access denied"}, 400)
    except SQLAlchemyError:
        session.rollback()
        return_req, code = ({"error": "SQLAlchemyError while editing user"}, 401)
        traceback.print_exc()
    finally:
        session.close()
    return return_req, code

def add_vault_entry(user_id, site, site_username, password_encrypted, notes=None):
    """Add a vault entry"""
    session = SessionLocal()
    try:
        entry = VaultEntry(
            user_id=user_id,
            site=site,
            site_username=site_username,
            password_encrypted=password_encrypted,
            notes=notes
        )
        session.add(entry)
        session.commit()
        print(f"Vault entry added for site: {site}")
    except ProgrammingError:
        print("Table not found. Did you create the tables?")
        traceback.print_exc()
    except SQLAlchemyError:
        session.rollback()
        print("Error adding vault entry:")
        traceback.print_exc()
    finally:
        session.close()

def get_user_by_username(username):
    """Fetch user object according to the username"""
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(username=username).first()
        return user, 200
    except SQLAlchemyError:
        return {"error": "SQLAlchemy while getting user"}, 401
        traceback.print_exc()
    finally:
        session.close()

def get_vault_entries_for_user(user_id):
    """Get all vault entries for user by user ID"""
    session = SessionLocal()
    try:
        entries = session.query(VaultEntry).filter_by(user_id=user_id).all()
        return entries
    except ProgrammingError:
        print("Table not found. Make sure to run create_tables() first.")
        traceback.print_exc()
    except SQLAlchemyError:
        print("Error fetching vault entries:")
        traceback.print_exc()
    finally:
        session.close()
