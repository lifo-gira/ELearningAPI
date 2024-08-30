from pydantic import BaseModel, EmailStr, Field
from typing import List, Dict, Optional


class GoogleOAuthToken(BaseModel):
    id_token: str

class GoogleOAuthUserData(BaseModel):
    type: Optional[str] = None
    user_id: str = None  # Will be populated after token verification
    first_name: str
    last_name: str
    email: EmailStr
    dob: str = None
    blood_grp: str = None
    flag: bool = True

    class Config:
        schema_extra = {
            "example": {
                "type": "patient",
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe@example.com",
                "dob": "22-08-2024",
                "blood_grp": "O+",
                "flag": True
            }
        }

class User(BaseModel):
    type: Optional[str] = None
    user_id: Optional[str] = None
    first_name: str
    last_name: str
    email: EmailStr
    dob: Optional[str] = None
    blood_grp: Optional[str] = None
    password: Optional[str] = None  # Make password optional
    flag: bool = True

    class Config:
        schema_extra = {
            "example": {
                "type": "patient",
                "first_name": "John",
                "last_name": "Doe",
                "email": "johndoe@example.com",
                "dob": "22-08-2024",
                "blood_grp": "O+",
                "flag": True
            }
        }


class ExerciseWithCategories(BaseModel):
    exercise_id: str
    exercise_name: str
    description: str = Field(..., min_length=10, max_length=500)

    class Config:
        schema_extra = {
            "example": {
                "exercise_id": "EX123",
                "exercise_name": "Running",
                "description": "Running is a cardiovascular exercise that improves cardiovascular health and endurance. It involves continuous movement and can be done outdoors or on a treadmill.",
            }
        }

class CategoryWithExercises(BaseModel):
    category: str
    exercises: List[ExerciseWithCategories]

class AllCategoriesResponse(BaseModel):
    categories: List[CategoryWithExercises]

class Exercise(BaseModel):
    exercise_id: str
    exercise_name: str
    description: str = Field(..., min_length=10, max_length=500)

class Category(BaseModel):
    category: str
    exercises: List[Exercise]

class ExerciseCategories(BaseModel):
    categories: List[Category]  # Now expects a list of Category objects

    class Config:
        schema_extra = {
            "example": {
                "categories": [
                    {
                        "category": "strength",
                        "exercises": [
                            {
                                "exercise_id": "EX127",
                                "exercise_name": "Push-Ups",
                                "description": "Push-ups are a bodyweight exercise that builds upper body strength and endurance. They primarily target the chest, shoulders, and triceps."
                            }
                        ]
                    }
                ]
            }
        }

class ExerciseDetails(BaseModel):
    exercise_description: str = Field(..., min_length=10, max_length=500)
    exercise_progress: float
    rep: int
    set: int

class ExercisesAssigned(BaseModel):
    exercise_name: str
    exercise_assigned: bool
    exercise_details: ExerciseDetails

class PatientDetails(BaseModel):
    patient_id: str
    patient_name: str
    patient_exercises: ExercisesAssigned

class Doctor(BaseModel):
    user_id: str
    first_name: str
    patients_assigned: Optional[List[PatientDetails]] = []  

    class Config:
        schema_extra = {
            "example": {
                "user_id": "WAD24D001",
                "first_name": "Joe",
                "patients_assigned": [
                    {
                        "patient_id": "WAD24P001",
                        "patient_name": "John Doe",
                        "patient_exercises": [
                            {
                                "exercise_name": "Push Ups",
                                "exercise_assigned": True,
                                "exercise_details": {
                                    "exercise_description": "Perform push-ups with proper form to build upper body strength.",
                                    "exercise_progress": 50.5,
                                    "rep": 15,
                                    "set": 3
                                }
                            },
                            {
                                "exercise_name": "Squats",
                                "exercise_assigned": True,
                                "exercise_details": {
                                    "exercise_description": "Perform squats to strengthen your legs and lower body.",
                                    "exercise_progress": 75.0,
                                    "rep": 20,
                                    "set": 4
                                }
                            }
                        ]
                    },
                    {
                        "patient_id": "WAD24P002",
                        "patient_name": "Jane Smith",
                        "patient_exercises": [
                            {
                                "exercise_name": "Bicep Curls",
                                "exercise_assigned": True,
                                "exercise_details": {
                                    "exercise_description": "Use dumbbells for bicep curls to increase arm strength.",
                                    "exercise_progress": 60.0,
                                    "rep": 12,
                                    "set": 3
                                }
                            }
                        ]
                    }
                ]
            }
        }