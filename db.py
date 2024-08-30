import os
from dotenv import load_dotenv
from motor import motor_asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime
from fastapi.security import OAuth2AuthorizationCodeBearer
from authlib.integrations.starlette_client import OAuth

load_dotenv()
oauth = OAuth()

# MongoDB setup
client = motor_asyncio.AsyncIOMotorClient("mongodb+srv://wadfirm2023:wadfirm2023@cluster0.83dqq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
# MONGO_URI = os.getenv("MONGO_URI")
# client = AsyncIOMotorClient(MONGO_URI)
database = client.Main
user_collection = database.User 
doctor_Collection = database.Doctor
exercise_collection = database.Exercise

# GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
# GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
# GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
# GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
# GOOGLE_TOKENINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/tokeninfo"

oauth.register(
    name='google',
    client_id="289659902472-lo5iqd93dcdse210nf2d8eqf7r30nt6m.apps.googleusercontent.com ",
    client_secret="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",
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    authorize_prompt_params=None,
    authorize_prompt_template=None,
    token_url='https://accounts.google.com/o/oauth2/token',
    # redirect_uri='https://localhost:3000/diagnostics'
)

def serialize_user(user):
    user_dict = user
    if '_id' in user_dict:
        user_dict['_id'] = str(user_dict['_id'])  # Convert ObjectId to string
    return user_dict

async def generate_user_id(user_type: str) -> str:
    current_year = datetime.now().year % 100  # Get the last two digits of the current year
    prefix = f"WAD{current_year}"
    
    if user_type.lower() == "patient":
        prefix += "P"
    elif user_type.lower() == "doctor":
        prefix += "D"
    else:
        raise ValueError("Invalid user type")

    # Count existing users of this type (await the result)
    existing_users = await user_collection.count_documents({"type": user_type})
    user_number = str(existing_users + 1)  # Increment without zero padding

    return f"{prefix}{user_number}"

async def generate_exercise_id() -> str:
    current_year = datetime.now().year % 100
    prefix = f"WAD{current_year}EX"

    # Find the highest existing exercise number
    highest_exercise = await exercise_collection.find_one(
        {},
        sort=[("exercises.exercise_id", -1)],  # Sort in descending order to get the highest ID
        projection={"exercises.exercise_id": 1}
    )

    if highest_exercise and highest_exercise.get("exercises"):
        # Extract the highest number from the latest exercise_id
        last_exercise_id = highest_exercise["exercises"][0]["exercise_id"]
        last_number = int(last_exercise_id[len(prefix):])
    else:
        last_number = 0

    # Increment and generate the new ID
    new_number = last_number + 1
    return f"{prefix}{new_number}"


async def get_existing_exercise_id(exercise_name: str) -> str:
    # Search for exercise by name across all categories
    existing_exercise = await exercise_collection.find_one(
        {"exercises.exercise_name": exercise_name},
        {"exercises.$": 1}  # Project only the matching exercise
    )
    if existing_exercise and existing_exercise.get("exercises"):
        # Return the ID of the first match
        return existing_exercise["exercises"][0]["exercise_id"]
    return None

