import os
import motor.motor_asyncio
from server.utils.exceptions import NotFoundException, ConnectionErrorException

user = os.environ.get('MONGO_ROOT_USER')
password = os.environ.get('MONGO_ROOT_PASSWORD')
MONGO_DETAILS = f"mongodb://{user}:{password}@mongodb1:27017"

try:
    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS, serverSelectionTimeoutMS=5000)

    database = client.users

    user_collection = database.get_collection("users_collection")

except Exception:
    raise ConnectionErrorException("Error connecting to database")


# helpers
    
# Retrieve all users present in the database
async def retrieve_users():
    users = []
    try:
        async for user in user_collection.find():
            users.append(user)
        return users
    except Exception:
        raise NotFoundException("Error occurred while retrieving users.")

# Add a new user into to the database
async def add_user(user_data: dict) -> dict:
    try:
        user_data["_id"]=user_data["phone_number"]
        user = await user_collection.insert_one(user_data)
        new_user = await user_collection.find_one({"_id": user.inserted_id})
        return new_user
    except Exception:
        raise NotFoundException("Error occurred while adding new user to database.")

# Retrieve a user with a matching ID
async def retrieve_user(id: str) -> dict:
    try:
        user = await user_collection.find_one({"_id": id})
        if user:
            return user
    except Exception:
        raise NotFoundException(f"Error occurred while retriving user {id}.")
    
# Retrieve a user with a matching query
async def retrieve_query(query: dict) -> dict:
    try:
        user = await user_collection.find_one(query)
        if user:
            return user
    except Exception:
        raise NotFoundException(f"Error occurred while retriving user {id}.")

# Update a user with a matching ID
async def update_user(id: str, data: dict):
    # Return false if an empty request body is sent.
    try:
        if len(data) < 1:
            return False
        user = await user_collection.find_one({"_id": id})
        print(user)
        if user:
            updated_user = await user_collection.update_one(
                {"_id": id}, {"$set": data}
            )
            if updated_user:
                return updated_user
            else:
                raise NotFoundException(f"Error occurred while updating user {id}.")
        else:
            raise NotFoundException(f"Error occurred while updating user {id}: User not found.")
    except Exception:
        raise NotFoundException(f"Error occurred while updating user {id}.")


# Delete a user from the database
async def delete_user(id: str):
    try:
        user = await user_collection.find_one({"_id": id})
        if user:
            await user_collection.delete_one({"_id": id})
            return True
    except Exception:
        raise NotFoundException(f"Error occurred while deleting user {id}.")