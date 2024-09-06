from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from models import GoogleOAuthToken, User, ExerciseWithCategories, CategoryWithExercises, AllCategoriesResponse, Exercise, ExerciseCategories, Doctor, PatientDetails
from db import serialize_user, user_collection, exercise_collection ,generate_exercise_id, get_existing_exercise_id, doctor_Collection
from db import generate_user_id
from google.auth.transport import requests
from typing import List, Dict
from models import GoogleOAuthToken, GoogleOAuthUserData
from fastapi.responses import RedirectResponse
import httpx, os
from authlib.integrations.starlette_client import OAuth
from bson import ObjectId
from google.oauth2 import id_token
from pydantic import BaseModel, EmailStr, Field
from pymongo.errors import DuplicateKeyError

app = FastAPI()
oauth = OAuth()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    authorize_prompt_params=None,
    authorize_prompt_template=None,
    token_url='https://accounts.google.com/o/oauth2/token',
    # redirect_uri='https://localhost:3000/diagnostics'
)

@app.get("/")
def root():
    return {"Message": "use '/docs' endpoint to find all the api related docs "}

# @app.post("/google-login")
# async def google_login(data: GoogleOAuthCallback):
#     try:
#         # Check if the user already exists in the database
#         existing_user = await user_collection.find_one({"email": data.email})
        
#         if existing_user:
#             # Log existing user details for debugging
#             print("Existing user found:", existing_user)
#             return {"message": "Login successful", "user_data": serialize_document(existing_user)}
#         else:
#             # User does not exist, create a new user record
#             new_user_data = {
#                 "user_id": data.user_id or str(ObjectId()),  # Generate a new user_id if not provided
#                 "first_name": data.first_name,
#                 "last_name": data.last_name,
#                 "email": data.email,
#                 "dob": data.dob,
#                 "blood_grp": data.blood_grp,
#                 "password": data.password,  # Typically not used for OAuth
#                 "flag": data.flag
#             }
#             # Insert the new user into the database
#             result = await user_collection.insert_one(new_user_data)
#             if result.inserted_id:
#                 return {"message": "User created successfully", "user_id": str(result.inserted_id)}
#             else:
#                 raise HTTPException(status_code=500, detail="Error creating user")
#     except Exception as e:
#         print(f"An error occurred: {e}")
#         raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/google-auth-callback")
async def google_auth_callback(token_data: GoogleOAuthToken):
    # Log ID token to console
    print("Received ID Token:", token_data.id_token)
    
    try:
        # Verify the ID token
        try:
            idinfo = id_token.verify_oauth2_token(token_data.id_token, requests.Request())
            print("ID Token Info:", idinfo)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=f"Token verification error: {str(ve)}")

        # Extract user information
        user_email = idinfo.get('email')
        if not user_email:
            raise ValueError("Email not found in ID token")
        
        user_info = {
            "type": "patient",
            "user_id": idinfo.get('sub'),
            "first_name": idinfo.get('given_name'),
            "last_name": idinfo.get('family_name'),
            "email": user_email,
            "dob": None,
            "blood_grp": None,
            "password": None,
            "flag": True
        }
        
        # Debugging statement: log user_email
        print("User Email from Token:", user_email)

        # Check if user exists in MongoDB
        user = await user_collection.find_one({"email": user_email})
        print("User found in DB:", user)

        if user:
            # User exists, return a login success response
            return {"status": "Login successful", "user_info": serialize_user(user)}
        else:
            # User does not exist, create a new user
            user_data = User(
                type=user_info.get('type'),
                user_id=user_info.get('user_id'),
                first_name=user_info.get('first_name'),
                last_name=user_info.get('last_name'),
                email=user_info.get('email'),
                dob=user_info.get('dob'),
                blood_grp=user_info.get('blood_grp'),
                flag=user_info.get('flag')
            )
            # Generate user ID
            user_data.user_id = await generate_user_id(user_data.type)
            
            # Insert new user into the database
            user_dict = user_data.dict()
            result = await user_collection.insert_one(user_dict)
            print("Insert Result:", result.inserted_id)

            if result.inserted_id:
                # If the user is a doctor, also create an entry in the Doctor collection
                if user_data.type.lower() == "doctor":
                    doctor_data = User(
                        user_id=user_data.user_id,
                        first_name=user_data.first_name
                    )
                    await doctor_Collection.insert_one(doctor_data.dict())

                return {"status": "User created successfully", "user_info": user_data.dict()}
            else:
                raise HTTPException(status_code=500, detail="Error creating user")
                
    except Exception as e:
        # Log and return error details
        print("Error:", str(e))
        raise HTTPException(status_code=400, detail=f"Invalid ID token or other error: {str(e)}")
                
    except Exception as e:
        # Log and return error details
        print("Error:", str(e))
        raise HTTPException(status_code=400, detail=f"Invalid ID token or other error: {str(e)}")
    
@app.get("/check_user/")
async def check_user(email: EmailStr = Query(...), password: str = Query(...)):
    # Query the database for the user by email
    user = await user_collection.find_one({"email": email})
    
    if user:
        # Get the stored password from the database
        stored_password = user.get("password")
        
        # Compare the provided password with the stored password
        if stored_password == password:
            # Convert the MongoDB ObjectId to a string for JSON serialization
            user["_id"] = str(user["_id"])
            
            # Remove the password from the response for security reasons
            user.pop("password", None)
            
            return {"status": "success", "message": "User authenticated", "user_details": user}
        else:
            raise HTTPException(status_code=401, detail="Invalid password")
    else:
        raise HTTPException(status_code=404, detail="User not found")

    
@app.get("/login_email/")
async def login(email: EmailStr = Query(...)):
    # Query the database for the user by email
    user = await user_collection.find_one({"email": email})
    
    if user:
        # Convert the MongoDB ObjectId to a string for JSON serialization
        user["_id"] = str(user["_id"])
        return {"status": "success", "message": "User found", "user_details": user}
    else:
        raise HTTPException(status_code=404, detail="User not found")

    
# @app.get("/auth/google/login")
# async def google_login():
#     # The URL to redirect the user to Google's OAuth 2.0 server
#     redirect_uri = "http://localhost:8000/auth/google/callback"
#     google_auth_url = (
#         f"{GOOGLE_AUTHORIZATION_ENDPOINT}?"
#         f"response_type=code&client_id={GOOGLE_CLIENT_ID}&"
#         f"redirect_uri={redirect_uri}&scope=openid%20email%20profile"
#     )
#     return RedirectResponse(google_auth_url)

# @app.get("/auth/google/callback")
# async def google_callback(code: str):
#     # Exchange code for an access token
#     async with httpx.AsyncClient() as client:
#         token_response = await client.post(
#             GOOGLE_TOKEN_ENDPOINT,
#             data={
#                 "code": code,
#                 "client_id": GOOGLE_CLIENT_ID,
#                 "client_secret": GOOGLE_CLIENT_SECRET,
#                 "redirect_uri": "http://localhost:8000/auth/google/callback",
#                 "grant_type": "authorization_code",
#             },
#             headers={"Content-Type": "application/x-www-form-urlencoded"},
#         )
#         token_response_json = token_response.json()
#         access_token = token_response_json.get("access_token")

#         if not access_token:
#             raise HTTPException(status_code=400, detail="Token not received")

#         # Use the access token to get user info
#         user_info_response = await client.get(
#             GOOGLE_USERINFO_ENDPOINT,
#             headers={"Authorization": f"Bearer {access_token}"},
#         )
#         user_info = user_info_response.json()

#         return {"user_info": user_info}
    
# @app.post("/auth/google/callback")
# async def google_callback(token: Token):
#     async with httpx.AsyncClient() as client:
#         token_info_response = await client.get(
#             f"{GOOGLE_TOKENINFO_ENDPOINT}?id_token={token.id_token}"
#         )
#         token_info = token_info_response.json()
        
#         if token_info.get("aud") != GOOGLE_CLIENT_ID:
#             raise HTTPException(status_code=400, detail="Invalid ID token")

#         # Process the user's information here
#         user_info = {
#             "sub": token_info.get("sub"),
#             "name": token_info.get("name"),
#             "email": token_info.get("email")
#         }

        # return {"user_info": user_info}

@app.post("/users/")
async def create_user(user: User):
    # Check if email already exists
    existing_user = await user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already in use")

    # Generate the user_id based on the type
    user.user_id = await generate_user_id(user.type)

    # Convert the user model to a dictionary
    user_dict = user.dict()

    try:
        # Insert the new user into the database
        result = await user_collection.insert_one(user_dict)

        if result.inserted_id:
            # If the user is a doctor, also create an entry in the Doctor collection
            if user.type and user.type.lower() == "doctor":
                doctor_data = Doctor(
                    user_id=user.user_id,
                    first_name=user.first_name
                )
                await doctor_Collection.insert_one(doctor_data.dict())

            return {"message": "User created successfully", "user_id": user.user_id}
        else:
            raise HTTPException(status_code=500, detail="Error creating user")
    except DuplicateKeyError:
        raise HTTPException(status_code=500, detail="Duplicate key error")

@app.get("/users/{user_id}", response_model=User)
async def get_user(user_id: str):
    user_data = await user_collection.find_one({"user_id": user_id})
    if user_data:
        return User(**user_data)
    raise HTTPException(status_code=404, detail="User not found")
    

# @app.post("/exercise/")
# async def create_exercise(exercise: Exercise):
#     exercise_dict = exercise.dict()  
#     result = await exercise_collection.insert_one(exercise_dict)  
#     if result:
#         return {"message": "Exercise created successfully"}
#     else:
#         raise HTTPException(status_code=500, detail="Error creating Exercise")
    
@app.get("/exercises/", response_model=List[Exercise])
async def get_all_exercises():
    try:
        # Fetch all documents from the collection
        cursor = exercise_collection.find()
        documents = await cursor.to_list(length=None)

        # Extract exercises from each document
        exercises = []
        for document in documents:
            # Log raw document data for debugging
            print("Raw document data:", document)

            # Ensure the 'exercises' field is present and is a list
            if 'exercises' in document and isinstance(document['exercises'], list):
                for exercise in document['exercises']:
                    # Ensure the exercise has the required fields
                    if all(key in exercise for key in ['exercise_id', 'exercise_name', 'description']):
                        exercise_data = {
                            'exercise_id': exercise['exercise_id'],
                            'exercise_name': exercise['exercise_name'],
                            'description': exercise['description']
                        }
                        exercises.append(Exercise(**exercise_data))
                    else:
                        print(f"Skipping exercise due to missing fields: {exercise}")
            else:
                print(f"Skipping document due to missing or invalid 'exercises' field: {document}")

        return exercises

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/add_category/")
async def add_category(exercise_categories: ExerciseCategories):
    for category_data in exercise_categories.categories:
        category_name = category_data.category
        exercises = category_data.exercises

        # Retrieve existing category or prepare for new category insertion
        existing_category = await exercise_collection.find_one({"category": category_name})

        updated_exercises = []

        for exercise in exercises:
            existing_exercise_id = await get_existing_exercise_id(exercise.exercise_name)

            if existing_exercise_id:
                # Use existing exercise ID
                updated_exercise = {**exercise.dict(), "exercise_id": existing_exercise_id}
            else:
                # Generate new exercise ID
                new_exercise_id = await generate_exercise_id()
                updated_exercise = {**exercise.dict(), "exercise_id": new_exercise_id}

            updated_exercises.append(updated_exercise)

        if existing_category:
            # Check current exercise IDs in the existing category
            existing_exercise_ids = {e["exercise_id"] for e in existing_category["exercises"]}
            # Filter out exercises that are not already in the existing category
            new_or_updated_exercises = [e for e in updated_exercises if e["exercise_id"] not in existing_exercise_ids]

            if new_or_updated_exercises:
                await exercise_collection.update_one(
                    {"_id": existing_category["_id"]},
                    {"$push": {"exercises": {"$each": new_or_updated_exercises}}}
                )
        else:
            # Insert new category with exercises
            await exercise_collection.insert_one({
                "category": category_name,
                "exercises": updated_exercises
            })

    return {"message": "Category and exercises added successfully"}



# @app.post("/add_exercise/")
# async def add_exercise(exercise_data: ExerciseWithCategories):
#     exercise_dict = exercise_data.dict()

#     for category_name in exercise_data.category:
#         existing_category = await exercise_collection.find_one({"category": category_name})

#         if existing_category:
#             # Check if exercise already exists in this category
#             existing_exercise_ids = {exercise["exercise_id"] for exercise in existing_category["exercises"]}
            
#             if exercise_data.exercise_id not in existing_exercise_ids:
#                 # Add the exercise to the category
#                 await exercise_collection.update_one(
#                     {"_id": existing_category["_id"]},
#                     {"$push": {"exercises": exercise_dict}}
#                 )
#         else:
#             # If category does not exist, create a new category document
#             await exercise_collection.insert_one({
#                 "category": category_name,
#                 "exercises": [exercise_dict]
#             })

#     return {"message": "Exercise added successfully to the specified categories"}


@app.get("/exercises_by_category/", response_model=CategoryWithExercises)
async def get_exercises_by_category(category: str = Query(..., description="The category to filter exercises by")):
    try:
        # Query the MongoDB collection for documents with the specified category
        cursor = exercise_collection.find({"category": category})
        documents = await cursor.to_list(length=None)

        if not documents:
            raise HTTPException(status_code=404, detail="No exercises found for the specified category")

        exercises = []
        for doc in documents:
            for exercise_doc in doc.get("exercises", []):
                exercise = ExerciseWithCategories(
                    exercise_id=exercise_doc.get("exercise_id", ""),
                    exercise_name=exercise_doc.get("exercise_name", ""),
                    description=exercise_doc.get("description", ""),
                    category=exercise_doc.get("category", [])
                )
                exercises.append(exercise)

        return CategoryWithExercises(
            category=category,
            exercises=exercises
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/assign-patient/")
async def assign_patient_to_doctor(doctor_id: str, doctor_name: str, patient: PatientDetails):
    # Validate the existence of the doctor in the database
    doctor = await doctor_Collection.find_one({"user_id": doctor_id, "first_name": doctor_name})

    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    # Ensure `patient_exercises` is always a list, even if it's empty or has a single element
    if not isinstance(patient.patient_exercises, list):
        patient.patient_exercises = [patient.patient_exercises]

    update_result = None  # Initialize update_result

    # Check if the patient already exists in the doctor's patients_assigned list
    patient_exists = False
    for idx, existing_patient in enumerate(doctor["patients_assigned"]):
        if existing_patient["patient_name"] == patient.patient_name:
            patient_exists = True
            
            # Prepare a list to keep track of exercises to update
            updates = []

            # Go through each new exercise and either update or add it
            for new_exercise in patient.patient_exercises:
                exercise_exists = False
                for existing_exercise in existing_patient["patient_exercises"]:
                    if existing_exercise["exercise_name"] == new_exercise.exercise_name:
                        exercise_exists = True
                        # Update the existing exercise details
                        updates.append({
                            "filter": {"$and": [
                                {"patient_name": patient.patient_name},
                                {"patient_exercises.exercise_name": new_exercise.exercise_name}
                            ]},
                            "update": {"$set": {f"patients_assigned.{idx}.patient_exercises.$.exercise_details": new_exercise.exercise_details.dict()}}
                        })
                        break
                
                if not exercise_exists:
                    updates.append({
                        "filter": {"user_id": doctor_id},
                        "update": {"$push": {f"patients_assigned.{idx}.patient_exercises": new_exercise.dict()}}
                    })

            # Execute all updates
            for update in updates:
                update_result = await doctor_Collection.update_one(update["filter"], update["update"])
            
            break

    # If the patient does not exist, add them to the patients_assigned list
    if not patient_exists:
        # Ensure no duplicate exercises are added
        new_patient_exercises = []
        for new_exercise in patient.patient_exercises:
            exercise_exists = False
            for existing_patient in doctor["patients_assigned"]:
                if existing_patient["patient_name"] == patient.patient_name:
                    for existing_exercise in existing_patient["patient_exercises"]:
                        if existing_exercise["exercise_name"] == new_exercise.exercise_name:
                            exercise_exists = True
                            break
                    if exercise_exists:
                        break

            if not exercise_exists:
                new_patient_exercises.append(new_exercise.dict())

        # Add patient with non-duplicate exercises
        if new_patient_exercises:
            update_result = await doctor_Collection.update_one(
                {"user_id": doctor_id},
                {"$push": {"patients_assigned": {**patient.dict(), "patient_exercises": new_patient_exercises}}}
            )

    if update_result and update_result.modified_count > 0:
        return {"message": f"Patient {patient.patient_name} and exercises assigned to Doctor {doctor_name}"}
    else:
        raise HTTPException(status_code=500, detail="Failed to assign patient or exercises")

    

@app.get("/doctor/")
async def get_doctor_details(doctor_id: str, doctor_name: str):
    # Find the doctor by user_id and first_name
    doctor = await doctor_Collection.find_one({"user_id": doctor_id, "first_name": doctor_name})
    
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Exclude the MongoDB internal '_id' field from the response
    doctor_data = {key: doctor[key] for key in doctor if key != "_id"}
    
    return doctor_data


@app.get("/patient/{patient_id}/")
async def get_patient_details(patient_id: str):
    # Iterate over all doctors to find the patient
    async for doctor in doctor_Collection.find():
        # Search through each doctor's assigned patients
        for patient in doctor.get("patients_assigned", []):
            if patient["patient_id"] == patient_id:
                return patient
    
    # If no patient is found with the given patient_id
    raise HTTPException(status_code=404, detail="Patient not found")


@app.get("/exercises", response_model=List[ExerciseWithCategories])
async def get_all_exercises():
    try:
        # Fetch all documents from the collection
        documents = await exercise_collection.find().to_list(length=None)
        
        # Use a dictionary to keep track of unique exercises by exercise_id
        unique_exercises = {}
        
        for document in documents:
            for exercise in document.get("exercises", []):
                # Add each exercise to the dictionary using exercise_id as the key
                unique_exercises[exercise["exercise_name"]] = ExerciseWithCategories(
                    exercise_id=exercise["exercise_id"],
                    exercise_name=exercise["exercise_name"],
                    description=exercise["description"]
                )
        
        # Return the values of the dictionary as a list
        return list(unique_exercises.values())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    
@app.get("/categories", response_model=List[str])
async def get_all_categories():
    try:
        # Fetch all documents from the collection
        documents = await exercise_collection.find().to_list(length=None)
        
        # Use a set to keep track of unique categories
        unique_categories = set()
        
        for document in documents:
            category = document.get("category")
            if category:
                unique_categories.add(category)
        
        # Return the unique categories as a list
        return list(unique_categories)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.put("/update_exercise_progress/")
async def update_exercise_progress(
    patient_id: str,
    patient_name: str,
    exercise_name: str,
    exercise_progress: float
):
    # Find the doctor by iterating through patients
    result = await doctor_Collection.update_one(
        {
            "patients_assigned": {
                "$elemMatch": {
                    "patient_id": patient_id,
                    "patient_name": patient_name,
                    "patient_exercises": {
                        "$elemMatch": {
                            "exercise_name": exercise_name
                        }
                    }
                }
            }
        },
        {
            "$set": {
                "patients_assigned.$[p].patient_exercises.$[e].exercise_details.exercise_progress": exercise_progress
            }
        },
        array_filters=[
            {"p.patient_id": patient_id, "p.patient_name": patient_name},
            {"e.exercise_name": exercise_name}
        ]
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Patient or exercise not found")
    
    return {"status": "success", "message": "Exercise progress updated"}
