from pymongo import MongoClient

client = MongoClient('mongodb+srv://sanilsurve42_db_user:96TuYmO3GgiEIV93@cluster0.0kbrfwv.mongodb.net/RoyalCars?appName=Cluster0')
db = client['RoyalCars']

count_before = db.bookings.count_documents({})
print(f'Bookings found: {count_before}')

result = db.bookings.delete_many({})
print(f'Deleted: {result.deleted_count} bookings')
print('Done — all bookings cleared.')
