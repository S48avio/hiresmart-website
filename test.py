from pymongo import MongoClient
client=MongoClient("mongodb+srv://saviosunny48:2TJsNwpNwqJX2aG3@cluster0.0zmwv1l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["HireSmart"]

signup_collection = db["Signup"]
result = signup_collection.insert_one({
    'full_name': 'Test User',
    'email': 'test@example.com',
    'password': 'dummy-hash',
    'role': 'Recruiter'
})
print(result.inserted_id)
