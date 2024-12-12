import os
import time
import hashlib
import firebase_admin
from datetime import datetime
from firebase_admin import credentials, firestore, storage
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.status import HTTP_404_NOT_FOUND, HTTP_405_METHOD_NOT_ALLOWED
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from firebase_admin import auth
from dotenv import load_dotenv


load_dotenv()
bearer_token = os.getenv("API_DB_BEARER_TOKEN")
bearer_token_header = APIKeyHeader(name="Authorization", auto_error=False)
firebase_file_adminsdk = os.getenv("FIREBASE_FILE_ADMINDSK")
firebase_storage_bucket = os.getenv("FIREBASE_STORAGE_BUCKET")


#  Autherization bearer token API
def verify_bearer_token(request_http: Request, token: str = Depends(bearer_token_header)):
    if token is None or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Eitss... mau ngapain? Akses terbatas!")
    actual_token = token[7:]
    if actual_token != bearer_token:
        raise HTTPException(status_code=401, detail="Invalid Token")


# Initialize firebase authentication
cred = credentials.Certificate(firebase_file_adminsdk)
firebase_admin.initialize_app(cred, {
    'storageBucket': firebase_storage_bucket
})
db = firestore.client()
bucket = storage.bucket()


# Class API model
class UserSignupManual(BaseModel):
    photo_url: str = None
    name: str = None
    email: str = None
    password: str = None
    role: str = None
    status: str = None
class CreateUserManual(BaseModel):
    name: str
    email: str
    password: str
    role: str
    status: str
class UserSignupGoogle(BaseModel):
    id_token: str
class UserSigninManual(BaseModel):
    email: str
    password: str
class UserSigninGoogle(BaseModel):
    id_token: str


# Metadata API
tags_metadata = [
    {
        "name": "root",
        "description": "Status API service."
    },
    {
        "name": "authentication",
        "description": "Sign up and Sign in User Account.",
    },
    {
        "name": "users",
        "description": "CRUD User Account.",
    },
]


# Initialize FastAPI
app = FastAPI(
    openapi_tags=tags_metadata,
    title="API Firebase Database Shavira Undiksha",
    summary="API Firebase Database Shavira Undiksha",
    version="0.0.1",
    root_path="/",
    docs_url="/docs",
    redoc_url="/help",
    openapi_url="/openapidb.json"
)


# CORS Headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Helper untuk mendapatkan waktu GMT+8
def get_current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Format API response
def api_response(status_code: int, success: bool, message: str, data=None):
    return JSONResponse(
        status_code=status_code,
        content={
            "statusCode": status_code,
            "success": success,
            "message": message,
            "data": data
        }
    )


# Enpoint untuk base url root API request
@app.get("/", tags=["root"])
async def root(request_http: Request, token: str = Depends(verify_bearer_token)):
    timestamp = get_current_time()
    return api_response(
        status_code=200,
        success=True,
        message="OK",
        data={"timestamp": timestamp, "description": "API Firebase Database Shavira Undiksha"}
    )


@app.post("/signup-manual", tags=["authentication"])
async def signup_manual(user: UserSignupManual, token: str = Depends(verify_bearer_token)):
    try:
        # Buat pengguna baru di Firebase Authentication
        user_record = auth.create_user(
            email=user.email,
            password=user.password,
            display_name=user.name,
            photo_url=user.photo_url
        )

        # Hash password untuk keamanan
        hashed_password = hashlib.sha256(user.password.encode()).hexdigest()

        # Simpan data pengguna di Firestore
        user_data = {
            "uid": user_record.uid,
            "photo_url": user.photo_url,
            "name": user.name,
            "email": user.email,
            "password": hashed_password,
            "role": user.role,
            "status": user.status,
            "type_user": "manual",
            "created_at": time.time(),
            "update_at": time.time()
        }
        db.collection("users").document(user_record.uid).set(user_data)
        return api_response(
            status_code=200,
            success=True,
            message="User created successfully",
            data=user_data
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/signin-manual", tags=["authentication"])
async def signin_manual(user: UserSigninManual, token: str = Depends(verify_bearer_token)):
    try:
        # Verifikasi email dan cek apakah user ada di Firebase Authentication
        try:
            user_record = auth.get_user_by_email(user.email)
        except firebase_admin.auth.UserNotFoundError:
            raise HTTPException(status_code=404, detail="User not found in Firebase Authentication")

        # Ambil data pengguna dari Firestore berdasarkan UID
        user_data = db.collection("users").document(user_record.uid).get().to_dict()

        # Jika data pengguna tidak ditemukan di Firestore
        if not user_data:
            raise HTTPException(status_code=404, detail="User data not found in Firestore")

        # Hash password untuk verifikasi
        hashed_password = hashlib.sha256(user.password.encode()).hexdigest()

        # Verifikasi password
        if user_data["password"] != hashed_password:
            raise HTTPException(status_code=401, detail="Invalid password")

        # Jika semua validasi lolos, kembalikan respons sukses
        return api_response(
            status_code=200,
            success=True,
            message="User signin successfully",
            data=user_data
        )

    except HTTPException as http_error:
        # Raise HTTPException langsung jika sudah ada
        raise http_error
    except Exception as e:
        # Tangani error lainnya
        raise HTTPException(status_code=500, detail="Internal server error")



@app.post("/signup-google", tags=["authentication"])
async def signup_google(user: UserSignupGoogle, token: str = Depends(verify_bearer_token)):
    try:
        # Verifikasi ID token dari Google
        decoded_token = auth.verify_id_token(user.id_token)
        uid = decoded_token['uid']
        email = decoded_token['email']
        name = decoded_token['name']

        # Cek apakah pengguna sudah ada di Firestore berdasarkan uid
        user_ref = db.collection("users").document(uid)
        doc = user_ref.get()
        if doc.exists:
            return {"message": "User already exists", "uid": uid}
        
        # Jika pengguna belum ada, buat data pengguna baru di Firestore
        user_data = {
            "uid": uid,
            "avatar": decoded_token.get('picture', ''),  # Avatar URL dari Google (opsional)
            "name": name,
            "email": email,
            "password": None,
            "role": "registered",
            "status": "active",
            "type_user": "google",
            "created_at": time.time(),
            "update_at": time.time()
        }
        user_ref.set(user_data)

        return api_response(
            status_code=200,
            success=True,
            message="User created successfully",
            data=user_data
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Google token or user exists")


@app.post("/signin-google", tags=["authentication"])
async def signin_google(user: UserSigninGoogle, token: str = Depends(verify_bearer_token)):
    try:
        # Verifikasi ID token dari Google
        decoded_token = auth.verify_id_token(user.id_token)
        uid = decoded_token['uid']

        # Ambil data pengguna dari Firestore
        user_data = db.collection("users").document(uid).get().to_dict()

        if not user_data:
            raise HTTPException(status_code=400, detail="User not found")

        return api_response(
            status_code=200,
            success=True,
            message="User signin successfully",
            data=user_data
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid Google token or user not found")


@app.post("/create-user", tags=["users"])
async def create_user(user: UserSignupManual, token: str = Depends(verify_bearer_token)):
    try:
        # Buat pengguna baru di Firebase Authentication
        user_record = auth.create_user(
            email=user.email,
            password=user.password,
            display_name=user.name
        )

        # Hash password untuk keamanan
        hashed_password = hashlib.sha256(user.password.encode()).hexdigest()

        # Simpan data pengguna di Firestore
        user_data = {
            "uid": user_record.uid,
            "name": user.name,
            "email": user.email,
            "password": hashed_password,
            "role": user.role,
            "status": user.status,
            "type_user": "manual",
            "created_at": time.time(),
            "update_at": time.time()
        }
        db.collection("users").document(user_record.uid).set(user_data)
        return api_response(
            status_code=200,
            success=True,
            message="User created successfully",
            data=user_data
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/read-users", tags=["users"])
async def list_users(token: str = Depends(verify_bearer_token)):
    try:
        # Ambil semua pengguna dari Firebase Authentication
        users = []
        page = auth.list_users()

        # Iterasi melalui semua pengguna di Firebase Authentication
        while page:
            for user_record in page.users:
                # Ambil data tambahan dari Firestore berdasarkan UID
                user_data_firestore = db.collection("users").document(user_record.uid).get().to_dict()
                
                if user_data_firestore:
                    # Gabungkan data dari Firestore
                    user_data = {
                        "uid": user_record.uid,
                        "photo_url": user_data_firestore.get("photo_url"),
                        "name": user_data_firestore.get("name"),
                        "email": user_data_firestore.get("email"),
                        "password": user_data_firestore.get("password"),
                        "role": user_data_firestore.get("role"),
                        "status": user_data_firestore.get("status"),
                        "type_user": user_data_firestore.get("type_user"),
                        "created_at": user_data_firestore.get("created_at"),
                        "update_at": user_data_firestore.get("update_at")
                    }
                    users.append(user_data)
                else:
                    # Jika tidak ada data di Firestore
                    users.append({
                        "uid": user_record.uid,
                        "error": "Data not found in Firestore"
                    })
            
            # Ambil halaman berikutnya (jika ada)
            page = page.get_next_page()

        # Jika tidak ada pengguna, kembalikan pesan khusus
        if not users:
            return api_response(
                status_code=200,
                success=True,
                message="No users found in Firebase Authentication or Firestore",
                data=None
            )

        return api_response(
            status_code=200,
            success=True,
            message="Users found in Firebase Authentication or Firestore",
            data=users
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.patch("/update-user/{uid}", tags=["users"])
async def update_user(uid: str, user: UserSignupManual, token: str = Depends(verify_bearer_token)):
    try:
        # Perbarui data di Firebase Authentication
        try:
            update_auth_params = {}
            if user.name:
                update_auth_params['display_name'] = user.name
            if user.photo_url:
                update_auth_params['photo_url'] = user.photo_url
            if user.password:
                update_auth_params['password'] = user.password

            # Jika ada perubahan di Firebase Authentication, lakukan update
            if update_auth_params:
                auth.update_user(uid, **update_auth_params)

        except firebase_admin.auth.UserNotFoundError:
            raise HTTPException(status_code=404, detail="User not found in Firebase Authentication")

        # Perbarui data di Firestore
        user_ref = db.collection("users").document(uid)
        user_data_firestore = user_ref.get().to_dict()

        if not user_data_firestore:
            raise HTTPException(status_code=404, detail="User data not found in Firestore")

        # Update Firestore fields
        update_firestore_params = {}
        if user.name:
            update_firestore_params['name'] = user.name
        if user.photo_url:
            update_firestore_params['photo_url'] = user.photo_url
        if user.password:
            hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
            update_firestore_params['password'] = hashed_password
        if user.role:
            update_firestore_params['role'] = user.role
        if user.status:
            update_firestore_params['status'] = user.status

        if update_firestore_params:
            update_firestore_params['update_at'] = time.time()
            user_ref.update(update_firestore_params)

        return api_response(
            status_code=200,
            success=True,
            message="User successfully updated",
            data={"uid": uid, "updated_fields": update_firestore_params}
        )

    except HTTPException as http_error:
        # Raise HTTPException langsung jika sudah ada
        raise http_error
    except Exception as e:
        # Tangani error lainnya
        raise HTTPException(status_code=500, detail="Internal server error")


@app.delete("/delete-user/{uid}", tags=["users"])
async def delete_user(uid: str, token: str = Depends(verify_bearer_token)):
    try:
        # Hapus pengguna dari Firebase Authentication
        try:
            auth.delete_user(uid)
        except firebase_admin.auth.UserNotFoundError:
            raise HTTPException(status_code=404, detail="User not found in Firebase Authentication")

        # Hapus data pengguna dari Firestore
        user_ref = db.collection("users").document(uid)
        if user_ref.get().exists:
            user_ref.delete()
        else:
            raise HTTPException(status_code=404, detail="User data not found in Firestore")

        return api_response(
            status_code=200,
            success=True,
            message="User successfully deleted",
            data={"uid": uid}
        )

    except HTTPException as http_error:
        # Raise HTTPException langsung jika sudah ada
        raise http_error
    except Exception as e:
        # Tangani error lainnya
        raise HTTPException(status_code=500, detail="Internal server error")


# Custom handler untuk 404 Not Found
@app.exception_handler(HTTP_404_NOT_FOUND)
async def not_found_handler(request: Request, exc: StarletteHTTPException):
    return api_response(
        status_code=404,
        success=False,
        message=f"{exc.detail}",
        data=None
    )


# Custom handler untuk 405 Method Not Allowed
@app.exception_handler(HTTP_405_METHOD_NOT_ALLOWED)
async def method_not_allowed_handler(request: Request, exc: StarletteHTTPException):
    return api_response(
        status_code=405,
        success=False,
        message=f"{exc.detail}",
        data=None
    )


# General handler untuk HTTP Exception lain
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return api_response(
        status_code=exc.status_code,
        success=False,
        message=f"{exc.detail}",
        data=None
    )


# General handler untuk validasi error
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    error_messages = "; ".join([f"{err['loc']}: {err['msg']}" for err in errors])
    return api_response(
        status_code=422,
        success=False,
        message=f"{error_messages}",
        data=None
    )