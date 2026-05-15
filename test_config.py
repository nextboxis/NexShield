from config import check_connection, _db_ready, client, users
print("check_connection:", check_connection())
print("_db_ready:", _db_ready)
print("client:", type(client))
print("users:", type(users))

try:
    print("trying to find one:", users.find_one({}))
except Exception as e:
    import traceback
    traceback.print_exc()
